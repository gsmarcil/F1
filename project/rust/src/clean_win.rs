//! Cleaning up after a stopped program on Windows: its file goes to quarantine, and whatever would start it
//! again is switched off (a file in a startup folder, a Run value, a scheduled task, a service). Everything is
//! written down first-to-last under the case, so `restore` puts it back.

#![cfg(windows)]

use crate::tool::run;
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

const MAX_ENTRY_BYTES: usize = 262_144;

fn is_key(key: &str) -> bool {
    key.len() == 32 && key.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn text(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

/// A path as Windows compares it: whole, and in lower case.
fn fold(path: &str) -> String {
    std::path::absolute(path).map(|whole| text(&whole)).unwrap_or_else(|_| path.to_string()).to_lowercase()
}

fn powershell(script: &str) -> bool {
    run(&["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", &format!("$ErrorActionPreference='Stop'; {script}")], None, Duration::from_secs(30)).is_some()
}

fn ps_json(script: &str) -> Vec<Value> {
    let whole = format!("$ErrorActionPreference='Stop'; [Console]::OutputEncoding=[Text.UTF8Encoding]::new(); {script}");
    let raw = run(&["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", &whole], None, Duration::from_secs(90)).unwrap_or_default();
    match serde_json::from_str::<Value>(raw.trim_start_matches('\u{feff}')) {
        Ok(Value::Array(list)) => list,
        Ok(value) if value.is_object() => vec![value],
        _ => Vec::new(),
    }
}

fn sorted_entries(folder: &Path, most: usize) -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = std::fs::read_dir(folder).map(|entries| entries.flatten().map(|entry| entry.path()).collect()).unwrap_or_default();
    found.sort();
    found.truncate(most);
    found
}

pub struct Cleaner {
    pub directory: PathBuf,
    root: PathBuf,
}

impl Cleaner {
    pub fn new(directory: &Path) -> Cleaner {
        let drive = std::env::var("SystemDrive").ok().filter(|value| !value.is_empty()).unwrap_or_else(|| "C:".into());
        Cleaner { directory: directory.to_path_buf(), root: PathBuf::from(format!("{drive}\\")) }
    }

    fn zones(&self) -> Vec<PathBuf> {
        let from = |name: &str, fallback: &str| std::env::var(name).ok().filter(|value| !value.is_empty()).map(PathBuf::from).unwrap_or_else(|| self.root.join(fallback));
        vec![self.root.join("Users"), from("ProgramData", "ProgramData"), from("SystemRoot", "Windows").join("Temp"), self.root.join("PerfLogs")]
    }

    fn homes(&self) -> Vec<PathBuf> {
        sorted_entries(&self.root.join("Users"), 200).into_iter().filter(|entry| std::fs::symlink_metadata(entry).is_ok_and(|meta| meta.is_dir())).collect()
    }

    /// The paths among these that are files an intruder could have put there: under a drop zone, a plain file,
    /// and not this agent or its own folder.
    pub fn removable(&self, paths: &[String]) -> Vec<String> {
        let exe = std::env::current_exe().ok();
        let own: Vec<String> = [Some(text(&self.directory)), exe.as_ref().and_then(|path| path.parent()).map(text), exe.as_ref().map(|path| text(path))]
            .into_iter().flatten().filter(|item| !item.is_empty()).map(|item| fold(&item)).collect();
        let under = |whole: &str, folder: &str| whole.starts_with(&format!("{}\\", folder.trim_end_matches(['\\', '/'])));
        let unique: BTreeSet<&String> = paths.iter().filter(|path| !path.is_empty()).collect();
        let mut found = Vec::new();
        for path in unique {
            let whole = fold(path);
            if own.iter().any(|item| whole == *item || under(&whole, item)) {
                continue;
            }
            if !self.zones().iter().any(|zone| under(&whole, &fold(&text(zone)))) {
                continue;
            }
            if !std::fs::symlink_metadata(path).is_ok_and(|meta| meta.is_file()) {
                continue;
            }
            found.push(path.clone());
        }
        found.truncate(16);
        found
    }

    fn move_away(&self, key: &str, path: &str, kind: &str) -> std::io::Result<Value> {
        let folder = self.directory.join("quarantine").join(key);
        std::fs::create_dir_all(&folder)?;
        let name: String = Path::new(path).file_name().map(|name| name.to_string_lossy().into_owned()).unwrap_or_default()
            .chars().map(|letter| if letter.is_ascii_alphanumeric() || matches!(letter, '.' | '_' | '-') { letter } else { '_' }).take(80).collect();
        let kept = folder.join(format!("{:02}-{}", std::fs::read_dir(&folder)?.count(), if name.is_empty() { "file" } else { &name }));
        let writable = !std::fs::metadata(path)?.permissions().readonly();
        let mut tries = 0;
        loop {
            // A program ended a moment ago can hold its file for an instant.
            match std::fs::rename(path, &kept).or_else(|_| std::fs::copy(path, &kept).and_then(|_| std::fs::remove_file(path))) {
                Ok(()) => break,
                Err(error) if tries >= 5 => return Err(error),
                Err(_) => {
                    tries += 1;
                    std::thread::sleep(Duration::from_millis(300));
                }
            }
        }
        if let Ok(meta) = std::fs::metadata(&kept) {
            let mut locked = meta.permissions();
            locked.set_readonly(true);
            let _ = std::fs::set_permissions(&kept, locked);
        }
        Ok(json!({"do": "moved", "kind": kind, "where": path, "kept": text(&kept), "mode": if writable { 0o666 } else { 0o444 }, "uid": 0, "gid": 0}))
    }

    /// Whatever would start one of these files, or call one of these addresses, again.
    fn clean_places(&self, key: &str, needles: &[String], steps: &mut Vec<Value>) {
        let low: Vec<String> = needles.iter().map(|needle| needle.to_lowercase()).collect();
        // Startup folders: a file there that names the program.
        let program_data = std::env::var("ProgramData").ok().filter(|value| !value.is_empty()).map(PathBuf::from).unwrap_or_else(|| self.root.join("ProgramData"));
        let mut folders = vec![program_data.join("Microsoft\\Windows\\Start Menu\\Programs\\StartUp")];
        folders.extend(self.homes().into_iter().map(|home| home.join("AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup")));
        for folder in folders {
            for entry in sorted_entries(&folder, 100) {
                if !entry.is_file() || entry.file_name().is_some_and(|name| name.to_string_lossy().to_lowercase() == "desktop.ini") {
                    continue;
                }
                let Ok(mut data) = std::fs::read(&entry) else { continue };
                data.truncate(MAX_ENTRY_BYTES);
                data.make_ascii_lowercase();
                let named = low.iter().any(|item| {
                    let wide: Vec<u8> = item.encode_utf16().flat_map(u16::to_le_bytes).collect();
                    let within = |needle: &[u8]| !needle.is_empty() && data.windows(needle.len()).any(|part| part == needle);
                    within(item.as_bytes()) || within(&wide)
                });
                if named {
                    if let Ok(step) = self.move_away(key, &text(&entry), "startup folder item") {
                        steps.push(step);
                    }
                }
            }
        }
        let list = low.iter().map(|item| quote(item)).collect::<Vec<_>>().join(",");
        let rows = ps_json(&format!("$n=@({list}); $o=@(); function Hit($v){{ $s=([string]$v).ToLower(); foreach($p in $n){{ if($s.Contains($p)){{ return $true }} }}; return $false }}; \
            $keys=@('HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run','HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce','HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run'); \
            foreach($u in @(Get-ChildItem Registry::HKEY_USERS -ErrorAction SilentlyContinue)){{ foreach($t in 'Run','RunOnce'){{ $keys+=('Registry::'+$u.Name+'\\Software\\Microsoft\\Windows\\CurrentVersion\\'+$t) }} }}; \
            foreach($k in $keys){{ $i=Get-Item -LiteralPath $k -ErrorAction SilentlyContinue; if($i){{ foreach($name in $i.GetValueNames()){{ $v=$i.GetValue($name,$null,'DoNotExpandEnvironmentNames'); if(Hit $v){{ $o+=[pscustomobject]@{{Type='run';Key=$k;Name=$name;Value=[string]$v;ValueKind=[string]$i.GetValueKind($name)}} }} }} }} }}; \
            foreach($t in @(Get-ScheduledTask -ErrorAction SilentlyContinue)){{ if([string]$t.State -ne 'Disabled'){{ foreach($a in @($t.Actions)){{ if(Hit ([string]$a.Execute+' '+[string]$a.Arguments)){{ $o+=[pscustomobject]@{{Type='task';Key=[string]$t.TaskPath;Name=[string]$t.TaskName;Value='';ValueKind=''}}; break }} }} }} }}; \
            foreach($s in @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue)){{ if([string]$s.StartMode -ne 'Disabled' -and (Hit $s.PathName)){{ $o+=[pscustomobject]@{{Type='service';Key='';Name=[string]$s.Name;Value=[string]$s.StartMode;ValueKind=''}} }} }}; \
            @($o | Select-Object -First 12) | ConvertTo-Json -Compress"));
        for row in rows {
            let (Some(name), Some(kind)) = (row["Name"].as_str().filter(|name| !name.is_empty()), row["Type"].as_str()) else { continue };
            let place = row["Key"].as_str().unwrap_or("");
            let value = row["Value"].as_str().unwrap_or("");
            match kind {
                "run" if powershell(&format!("Remove-ItemProperty -LiteralPath {} -Name {}", quote(place), quote(name))) => {
                    steps.push(json!({"do": "run", "kind": "startup entry", "where": format!("{place} : {name}"), "key": place, "name": name, "value": value, "expand": row["ValueKind"] == "ExpandString"}));
                }
                "task" if powershell(&format!("Disable-ScheduledTask -TaskPath {} -TaskName {} | Out-Null", quote(place), quote(name))) => {
                    steps.push(json!({"do": "task", "kind": "scheduled task", "where": format!("{place}{name}"), "path": place, "name": name}));
                }
                "service" if !matches!(name.to_lowercase().as_str(), "garrett" | "garrett-service")
                    && powershell(&format!("Stop-Service -Name {0} -Force -ErrorAction SilentlyContinue; Set-Service -Name {0} -StartupType Disabled", quote(name))) => {
                    steps.push(json!({"do": "service", "kind": "service", "where": name, "name": name, "start": if value == "Manual" { "Manual" } else { "Automatic" }}));
                }
                _ => {}
            }
        }
    }

    fn said(steps: &[Value]) -> Vec<Value> {
        let tidy = |value: &str, limit: usize| crate::score::clean(value, limit);
        steps.iter().map(|step| {
            let word = match step["do"].as_str().unwrap_or("") {
                "moved" => "quarantined",
                "commented" | "run" | "task" | "service" => "disabled",
                "review" => "review",
                _ => "left",
            };
            json!({"action": word, "kind": tidy(step["kind"].as_str().unwrap_or(""), 40), "where": tidy(step["where"].as_str().unwrap_or(""), 200)})
        }).collect()
    }

    /// Take away these program files and switch off whatever would start them again, or would call one of these
    /// known-bad addresses again. Returns what was done, for the case.
    pub fn clean(&self, key: &str, paths: &[String], addresses: &[String], now: f64) -> Vec<Value> {
        if !is_key(key) {
            return Vec::new();
        }
        let mut steps: Vec<Value> = Vec::new();
        let files = self.removable(paths);
        let mut needles: Vec<String> = files.iter().filter(|path| path.len() >= 6).cloned().collect();
        needles.extend(addresses.iter().collect::<BTreeSet<_>>().into_iter().filter(|address| address.len() >= 7).cloned());
        needles.truncate(24);
        // What starts it again goes first, while the entries still name a file that exists.
        if !needles.is_empty() {
            self.clean_places(key, &needles, &mut steps);
        }
        for path in &files {
            match self.move_away(key, path, "program file") {
                Ok(step) => steps.push(step),
                Err(_) => steps.push(json!({"do": "failed", "kind": "program file", "where": path})),
            }
        }
        if !steps.is_empty() {
            self.record(key, &steps, now);
        }
        let mut said = Self::said(&steps);
        said.truncate(12);
        said
    }

    /// Switch off one startup entry that was just judged, by itself. Returns what was done, for the case.
    pub fn disable(&self, key: &str, item: &crate::startup_win::Item, now: f64) -> Vec<Value> {
        use crate::startup_win::Detail;
        if !is_key(key) {
            return Vec::new();
        }
        let mut steps: Vec<Value> = Vec::new();
        match &item.detail {
            Detail::File => {
                if let Ok(step) = self.move_away(key, &item.where_, "startup folder item") {
                    steps.push(step);
                }
            }
            Detail::Run { key: place, name, value, expand } => {
                if powershell(&format!("Remove-ItemProperty -LiteralPath {} -Name {}", quote(place), quote(name))) {
                    steps.push(json!({"do": "run", "kind": "startup entry", "where": format!("{place} : {name}"), "key": place, "name": name, "value": value, "expand": expand}));
                }
            }
            Detail::Task { path, name } => {
                if powershell(&format!("Disable-ScheduledTask -TaskPath {} -TaskName {} | Out-Null", quote(path), quote(name))) {
                    steps.push(json!({"do": "task", "kind": "scheduled task", "where": format!("{path}{name}"), "path": path, "name": name}));
                }
            }
            Detail::Service { name, start } => {
                if !matches!(name.to_lowercase().as_str(), "garrett" | "garrett-service")
                    && powershell(&format!("Stop-Service -Name {0} -Force -ErrorAction SilentlyContinue; Set-Service -Name {0} -StartupType Disabled", quote(name))) {
                    steps.push(json!({"do": "service", "kind": "service", "where": name, "name": name, "start": if *start == 3 { "Manual" } else { "Automatic" }}));
                }
            }
        }
        if !steps.is_empty() {
            self.record(key, &steps, now);
        }
        Self::said(&steps)
    }

    fn record(&self, key: &str, steps: &[Value], now: f64) {
        let records = self.directory.join("cleanup");
        let _ = std::fs::create_dir_all(&records);
        let path = records.join(format!("{key}.json"));
        let mut all: Vec<Value> = std::fs::read(&path).ok().and_then(|raw| serde_json::from_slice::<Value>(&raw).ok()).and_then(|value| value["steps"].as_array().cloned()).unwrap_or_default();
        all.extend(steps.iter().cloned());
        let temporary = records.join(format!("{key}.tmp"));
        if std::fs::write(&temporary, json!({"at": now.trunc() as i64, "steps": all}).to_string()).is_ok() {
            let _ = std::fs::rename(&temporary, &path);
        }
    }

    /// Put back everything cleaned under this case. Returns (put back, could not be put back).
    pub fn restore(&self, key: &str, now: f64) -> (usize, usize) {
        if !is_key(key) {
            return (0, 0);
        }
        let path = self.directory.join("cleanup").join(format!("{key}.json"));
        let Some(steps) = std::fs::read(&path).ok().and_then(|raw| serde_json::from_slice::<Value>(&raw).ok()).and_then(|value| value["steps"].as_array().cloned()) else { return (0, 0) };
        let (mut back, mut left) = (0usize, Vec::new());
        for step in steps.iter().rev() {
            let word = |name: &str| step[name].as_str().unwrap_or("");
            let done = match word("do") {
                "moved" => {
                    let (kept, place) = (Path::new(word("kept")), Path::new(word("where")));
                    let unlock = |path: &Path, readonly: bool| {
                        if let Ok(meta) = std::fs::metadata(path) {
                            let mut permissions = meta.permissions();
                            permissions.set_readonly(readonly);
                            let _ = std::fs::set_permissions(path, permissions);
                        }
                    };
                    if kept.exists() && std::fs::symlink_metadata(place).is_err() {
                        unlock(kept, false); // it was locked in quarantine; unlocked to be moved back
                        if let Some(parent) = place.parent() {
                            let _ = std::fs::create_dir_all(parent);
                        }
                        let moved = std::fs::rename(kept, place).or_else(|_| std::fs::copy(kept, place).and_then(|_| std::fs::remove_file(kept))).is_ok();
                        if moved && step["mode"].as_u64().is_some_and(|mode| mode & 0o200 == 0) {
                            unlock(place, true);
                        }
                        moved
                    } else {
                        false
                    }
                }
                "run" => powershell(&format!("New-ItemProperty -LiteralPath {} -Name {} -Value {} -PropertyType {} -Force | Out-Null", quote(word("key")), quote(word("name")), quote(word("value")), if step["expand"] == true { "ExpandString" } else { "String" })),
                "task" => powershell(&format!("Enable-ScheduledTask -TaskPath {} -TaskName {} | Out-Null", quote(word("path")), quote(word("name")))),
                "service" => powershell(&format!("Set-Service -Name {} -StartupType {}", quote(word("name")), if word("start") == "Manual" { "Manual" } else { "Automatic" })),
                _ => continue, // review and failed steps changed nothing
            };
            if done {
                back += 1;
                // The startup watch will see it come back: it was put back on purpose, so it is not judged again.
                if word("do") != "moved" || word("kind") == "startup folder item" {
                    crate::startup_win::allow(&self.directory, word("where"));
                }
            } else {
                left.push(step.clone());
            }
        }
        // What could not be put back stays on record, so it can be tried again; first to last, as it was written.
        left.reverse();
        if left.is_empty() {
            let _ = std::fs::remove_file(&path);
            let _ = std::fs::remove_dir_all(self.directory.join("quarantine").join(key));
        } else {
            let _ = std::fs::write(&path, json!({"at": now.trunc() as i64, "steps": left}).to_string());
        }
        (back, left.len())
    }

    /// Case keys that have something in quarantine or switched off.
    pub fn cleaned(&self) -> Vec<String> {
        let mut found: Vec<String> = std::fs::read_dir(self.directory.join("cleanup")).map(|entries| entries.flatten().filter_map(|entry| {
            let path = entry.path();
            (path.extension().is_some_and(|kind| kind == "json")).then(|| path.file_stem().map(|stem| stem.to_string_lossy().into_owned())).flatten()
        }).collect()).unwrap_or_default();
        found.sort();
        found
    }
}
