//! Undo what a stopped program left behind, in a way that can itself be undone, and notice a startup entry the
//! moment one appears.
//!
//! A program's file is moved to a quarantine folder, not deleted. What would start it again is switched off: a
//! startup file is moved to quarantine, a line in a shared file is commented out. Every step is recorded under the
//! case, and `restore` puts everything back.
//!
//! The folder the machine's files start at is a parameter, so all of this is proven on made-up machines
//! (tests/fixtures/clean.jsonl) before it touches a real one.

use crate::score::clean as tidy;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::io::Write;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

pub const DISABLED_MARK: &str = "# garrett-disabled ";
pub const ALLOWED_FILE: &str = "sentinel-startup-allowed.json";
pub const STARTUP_FILE: &str = "sentinel-startup.json";
pub const MAX_ENTRY_BYTES: u64 = 262_144;
const LINUX_ZONES: &[&str] = &["tmp", "var/tmp", "dev/shm", "run/user", "home", "root", "var/www", "srv"];
const MACOS_ZONES: &[&str] = &["tmp", "private/tmp", "var/tmp", "private/var/tmp", "var/folders", "private/var/folders", "Users", "var/root", "private/var/root"];

fn text(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn is_key(key: &str) -> bool {
    key.len() == 32 && key.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// A path with `.`, `..` and doubled separators taken out, made absolute. Nothing is looked up on disk.
fn absolute(path: &str) -> String {
    let joined = if path.starts_with('/') { PathBuf::from(path) } else { std::env::current_dir().unwrap_or_default().join(path) };
    let mut parts: Vec<&str> = Vec::new();
    let whole = text(&joined);
    for part in whole.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            other => parts.push(other),
        }
    }
    format!("/{}", parts.join("/"))
}

fn trimmed(line: &[u8]) -> &[u8] {
    let blank = |byte: &u8| matches!(byte, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c);
    let start = line.iter().position(|byte| !blank(byte)).unwrap_or(line.len());
    let end = line.iter().rposition(|byte| !blank(byte)).map(|at| at + 1).unwrap_or(start);
    &line[start..end]
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    needle.is_empty() || haystack.windows(needle.len()).any(|window| window == needle)
}

fn sorted_entries(folder: &Path, limit: usize) -> Option<Vec<PathBuf>> {
    let mut found: Vec<PathBuf> = std::fs::read_dir(folder).ok()?.filter_map(|entry| entry.ok().map(|entry| entry.path())).collect();
    found.sort();
    found.truncate(limit);
    Some(found)
}

fn plain_file(path: &Path) -> bool {
    std::fs::symlink_metadata(path).map(|meta| !meta.file_type().is_symlink()).unwrap_or(false) && path.is_file()
}

fn quiet(arguments: &[&str]) {
    let _ = std::process::Command::new(arguments[0]).args(&arguments[1..]).stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).status();
}

/// The marks of a startup file's lines: one per line that is not blank and not a comment, in the file's order.
/// A mark is never the line itself.
pub fn marks(raw: &[u8]) -> Vec<(String, Vec<u8>)> {
    let mut found: Vec<(String, Vec<u8>)> = Vec::new();
    for line in raw.split(|byte| *byte == b'\n') {
        let stripped = trimmed(line);
        if stripped.is_empty() || stripped.starts_with(b"#") {
            continue;
        }
        let mark: String = Sha256::digest(stripped).iter().take(8).map(|byte| format!("{byte:02x}")).collect();
        match found.iter_mut().find(|(known, _)| *known == mark) {
            Some(entry) => entry.1 = stripped.to_vec(),
            None => found.push((mark, stripped.to_vec())),
        }
    }
    found
}

pub struct Cleaner {
    pub system: String,
    pub directory: PathBuf,
    pub root: PathBuf,
    /// Set when `root` is a container's file system seen from this machine: paths are given and reported as this
    /// machine sees them; startup entries inside the container name them without that prefix.
    pub prefix: String,
}

impl Cleaner {
    pub fn new(system: &str, directory: &Path, root: Option<&Path>, inside: bool) -> Cleaner {
        Cleaner {
            system: system.to_string(), directory: directory.to_path_buf(), root: root.map(Path::to_path_buf).unwrap_or_else(|| PathBuf::from("/")),
            prefix: if inside { root.map(text).unwrap_or_default() } else { String::new() },
        }
    }

    fn zones(&self) -> Vec<PathBuf> {
        let zones = if self.system == "macos" { MACOS_ZONES } else if self.system == "linux" { LINUX_ZONES } else { &[] };
        zones.iter().map(|zone| self.root.join(zone)).collect()
    }

    /// Inside a container: no folder on the way is a link, which could lead out to this machine's own files.
    fn plain(&self, path: &str) -> bool {
        let rest = Path::new(&path[self.prefix.len().min(path.len())..]).parent().map(text).unwrap_or_default();
        let mut here = self.prefix.clone();
        for part in rest.split('/').filter(|part| !part.is_empty()) {
            here = format!("{here}/{part}");
            if std::fs::symlink_metadata(&here).map(|meta| meta.file_type().is_symlink()).unwrap_or(false) {
                return false;
            }
        }
        path.starts_with(&format!("{}/", self.prefix))
    }

    /// The paths among these that are files an intruder could have put there: under a drop zone, a plain file,
    /// and not this agent or its own folder.
    pub fn removable(&self, paths: &[String]) -> Vec<String> {
        let exe = std::env::current_exe().ok();
        let own: Vec<String> = [Some(text(&self.directory)), exe.as_ref().and_then(|path| path.parent()).map(text), exe.as_ref().map(|path| text(path))]
            .into_iter().flatten().filter(|item| !item.is_empty()).map(|item| absolute(&item)).collect();
        let unique: BTreeSet<&String> = paths.iter().filter(|path| !path.is_empty()).collect();
        let mut found = Vec::new();
        for path in unique {
            let whole = absolute(path);
            if own.iter().any(|item| whole == *item || whole.starts_with(&format!("{}/", item.trim_end_matches('/')))) {
                continue;
            }
            if !self.zones().iter().any(|zone| whole.starts_with(&format!("{}/", text(zone).trim_end_matches('/')))) {
                continue;
            }
            if !plain_file(Path::new(path)) || (!self.prefix.is_empty() && !self.plain(path)) {
                continue;
            }
            found.push(path.clone());
        }
        found.truncate(16);
        found
    }

    fn quarantine(&self) -> PathBuf {
        self.directory.join("quarantine")
    }

    fn records(&self) -> PathBuf {
        self.directory.join("cleanup")
    }

    fn make_private(folder: &Path) -> std::io::Result<()> {
        if !folder.exists() {
            std::fs::create_dir_all(folder)?;
            std::fs::set_permissions(folder, std::fs::Permissions::from_mode(0o700))?;
        }
        Ok(())
    }

    fn carry(from: &Path, to: &Path) -> std::io::Result<()> {
        if std::fs::rename(from, to).is_ok() {
            return Ok(());
        }
        // Another file system: copied with its permissions and times, then the original removed.
        std::fs::copy(from, to)?;
        std::fs::remove_file(from)
    }

    fn move_away(&self, key: &str, path: &str, kind: &str) -> std::io::Result<Value> {
        let folder = self.quarantine().join(key);
        Self::make_private(&folder)?;
        let count = std::fs::read_dir(&folder)?.count();
        let base = Path::new(path).file_name().map(|name| name.to_string_lossy().into_owned()).unwrap_or_default();
        let safe: String = base.chars().map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-' { c } else { '_' }).take(80).collect();
        let kept = folder.join(format!("{count:02}-{}", if safe.is_empty() { "file" } else { &safe }));
        let status = std::fs::metadata(path)?;
        let mut tries = 0;
        loop {
            match Self::carry(Path::new(path), &kept) {
                Ok(()) => break,
                Err(error) if tries == 5 => return Err(error),
                Err(_) => {
                    tries += 1;
                    std::thread::sleep(std::time::Duration::from_millis(300)); // a program ended a moment ago can hold its file for an instant
                }
            }
        }
        let _ = std::fs::set_permissions(&kept, std::fs::Permissions::from_mode(0)); // nothing can run it from here
        Ok(json!({"do": "moved", "kind": kind, "where": path, "kept": text(&kept), "mode": status.mode() & 0o7777, "uid": status.uid(), "gid": status.gid()}))
    }

    /// Comment out the lines that name a needle (or, when `exact`, the lines that are exactly one of them).
    fn comment(&self, key: &str, path: &str, needles: &[Vec<u8>], kind: &str, exact: bool) -> std::io::Result<Option<Value>> {
        let raw = std::fs::read(path)?;
        let mark = format!("{DISABLED_MARK}{key}: ").into_bytes();
        let mut changed = 0;
        let lines: Vec<Vec<u8>> = raw.split(|byte| *byte == b'\n').map(|line| {
            let stripped = trimmed(line);
            let hit = if exact { needles.iter().any(|needle| needle.as_slice() == stripped) } else { needles.iter().any(|needle| contains(line, needle)) };
            if !stripped.is_empty() && !stripped.starts_with(b"#") && hit {
                changed += 1;
                [mark.as_slice(), line].concat()
            } else {
                line.to_vec()
            }
        }).collect();
        if changed == 0 {
            return Ok(None);
        }
        // The same file, so its owner and permissions stay as they were.
        let mut handle = std::fs::OpenOptions::new().write(true).open(path)?;
        let body = lines.join(&b'\n');
        handle.write_all(&body)?;
        handle.set_len(body.len() as u64)?;
        Ok(Some(json!({"do": "commented", "kind": kind, "where": path, "lines": changed})))
    }

    fn homes(&self) -> Vec<PathBuf> {
        let parent = if self.system == "macos" { "Users" } else { "home" };
        let mut homes: Vec<PathBuf> = sorted_entries(&self.root.join(parent), 200).unwrap_or_default().into_iter()
            .filter(|entry| entry.is_dir() && std::fs::symlink_metadata(entry).map(|meta| !meta.file_type().is_symlink()).unwrap_or(false)).collect();
        if self.system == "linux" {
            homes.push(self.root.join("root"));
        } else if self.system == "macos" {
            homes.push(self.root.join("var/root"));
        }
        homes
    }

    /// The folders startup entries live in, whether or not anything is in them yet.
    pub fn startup_folders(&self) -> Vec<PathBuf> {
        let mut folders: Vec<PathBuf> = ["etc", "etc/cron.d", "etc/systemd/system", "var/spool/cron", "var/spool/cron/crontabs", "Library/LaunchDaemons", "Library/LaunchAgents"].iter().map(|name| self.root.join(name)).collect();
        for home in self.homes() {
            folders.extend([home.clone(), home.join(".config/systemd/user"), home.join(".config/autostart"), home.join("Library/LaunchAgents")]);
        }
        folders
    }

    /// (kind, file, whole): `whole` is true when the whole file is the entry, false when it is a shared file of lines.
    pub fn places(&self) -> Vec<(&'static str, PathBuf, bool)> {
        let root = &self.root;
        let mut folders: Vec<(&'static str, PathBuf)> = vec![("startup service", root.join("etc/systemd/system")), ("scheduled job", root.join("etc/cron.d")),
            ("startup service", root.join("Library/LaunchDaemons")), ("login item", root.join("Library/LaunchAgents"))];
        let mut shared: Vec<(&'static str, PathBuf)> = vec![("scheduled job", root.join("etc/crontab")), ("startup script", root.join("etc/rc.local"))];
        for home in self.homes() {
            folders.extend([("startup service", home.join(".config/systemd/user")), ("login item", home.join(".config/autostart")), ("login item", home.join("Library/LaunchAgents"))]);
            shared.extend([".bashrc", ".profile", ".bash_profile", ".zshrc", ".zprofile"].iter().map(|name| ("shell startup file", home.join(name))));
            shared.push(("sign-in key", home.join(".ssh/authorized_keys")));
        }
        let mut places: Vec<(&'static str, PathBuf, bool)> = Vec::new();
        for (kind, folder) in folders {
            if let Some(entries) = sorted_entries(&folder, 300) {
                places.extend(entries.into_iter().filter(|entry| plain_file(entry)).map(|entry| (kind, entry, true)));
            }
        }
        for folder in [root.join("var/spool/cron/crontabs"), root.join("var/spool/cron")] {
            if let Some(entries) = sorted_entries(&folder, 300) {
                shared.extend(entries.into_iter().filter(|entry| plain_file(entry)).map(|entry| ("scheduled job", entry)));
            }
        }
        places.extend(shared.into_iter().map(|(kind, entry)| (kind, entry, false)));
        places
    }

    fn clean_places(&self, key: &str, needles: &[Vec<u8>], steps: &mut Vec<Value>) {
        let real = self.root == Path::new("/");
        let mut reload = false;
        for (kind, entry, whole) in self.places() {
            let readable = plain_file(&entry) && std::fs::metadata(&entry).map(|meta| meta.len() <= MAX_ENTRY_BYTES).unwrap_or(false);
            let Some(body) = readable.then(|| std::fs::read(&entry).ok()).flatten() else { continue };
            if !needles.iter().any(|needle| contains(&body, needle)) {
                continue;
            }
            let where_ = text(&entry);
            let done = if whole {
                if real && kind == "startup service" && entry.parent() == Some(&self.root.join("etc/systemd/system")) {
                    quiet(&["systemctl", "disable", "--now", &entry.file_name().map(|name| name.to_string_lossy().into_owned()).unwrap_or_default()]);
                    reload = true;
                } else if real && entry.parent() == Some(&self.root.join("Library/LaunchDaemons")) {
                    quiet(&["launchctl", "bootout", "system", &where_]);
                }
                self.move_away(key, &where_, kind).map(Some)
            } else {
                self.comment(key, &where_, needles, kind, false)
            };
            match done {
                Ok(Some(step)) => steps.push(step),
                Ok(None) => {}
                Err(_) => steps.push(json!({"do": "failed", "kind": kind, "where": where_})), // found, and it could not be changed: said, not hidden
            }
        }
        if reload {
            quiet(&["systemctl", "daemon-reload"]);
        }
    }

    /// Things an intruder commonly changes that only a person can judge: listed, never touched.
    fn review(&self, since: f64, steps: &mut Vec<Value>) {
        if since == 0.0 {
            return;
        }
        let mut watched: Vec<(&str, PathBuf)> = vec![("accounts", self.root.join("etc/passwd")), ("administrator rights", self.root.join("etc/sudoers"))];
        watched.extend(sorted_entries(&self.root.join("etc/sudoers.d"), 50).unwrap_or_default().into_iter().map(|entry| ("administrator rights", entry)));
        watched.extend(self.homes().into_iter().map(|home| ("sign-in keys", home.join(".ssh/authorized_keys"))));
        for (kind, entry) in watched {
            let Ok(meta) = std::fs::metadata(&entry) else { continue };
            if meta.is_file() && meta.mtime() as f64 + meta.mtime_nsec() as f64 / 1e9 >= since - 60.0 {
                steps.push(json!({"do": "review", "kind": kind, "where": text(&entry)}));
            }
        }
    }

    fn said(steps: &[Value]) -> Vec<Value> {
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
    pub fn clean(&self, key: &str, paths: &[String], addresses: &[String], since: f64, now: f64) -> Vec<Value> {
        if !is_key(key) {
            return Vec::new();
        }
        let mut steps: Vec<Value> = Vec::new();
        let files = self.removable(paths);
        let mut needles: Vec<Vec<u8>> = files.iter().map(|path| if !self.prefix.is_empty() && path.starts_with(&self.prefix) { path[self.prefix.len()..].to_string() } else { path.clone() })
            .filter(|seen| seen.len() >= 6).map(String::into_bytes).collect();
        needles.extend(addresses.iter().collect::<BTreeSet<_>>().into_iter().filter(|address| address.len() >= 7).map(|address| address.clone().into_bytes()));
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
        if !files.is_empty() {
            self.review(since, &mut steps);
        }
        if !steps.is_empty() {
            self.record(key, &steps, now);
        }
        let mut said = Self::said(&steps);
        said.truncate(12);
        said
    }

    /// Switch off one startup entry that has just appeared: the whole file when it is new, otherwise only the
    /// lines that were added.
    pub fn disable(&self, key: &str, kind: &str, where_: &str, whole: bool, lines: &[Vec<u8>], now: f64) -> Vec<Value> {
        if !is_key(key) || !plain_file(Path::new(where_)) {
            return Vec::new();
        }
        let mut steps: Vec<Value> = Vec::new();
        let done = if whole {
            self.move_away(key, where_, kind).map(Some)
        } else {
            let wanted: Vec<Vec<u8>> = lines.iter().map(|line| trimmed(line).to_vec()).filter(|line| !line.is_empty()).collect();
            self.comment(key, where_, &wanted, kind, true)
        };
        match done {
            Ok(Some(step)) => steps.push(step),
            Ok(None) => {}
            Err(_) => steps.push(json!({"do": "failed", "kind": kind, "where": where_})),
        }
        if !steps.is_empty() {
            self.record(key, &steps, now);
        }
        Self::said(&steps)
    }

    fn record(&self, key: &str, steps: &[Value], now: f64) {
        let folder = self.records();
        if Self::make_private(&folder).is_err() {
            return;
        }
        let path = folder.join(format!("{key}.json"));
        let mut all: Vec<Value> = std::fs::read(&path).ok().and_then(|raw| serde_json::from_slice::<Value>(&raw).ok()).and_then(|value| value["steps"].as_array().cloned()).unwrap_or_default();
        all.extend(steps.iter().cloned());
        let temporary = folder.join(format!("{key}.tmp"));
        if std::fs::write(&temporary, json!({"at": now.trunc() as i64, "steps": all}).to_string()).is_ok() {
            let _ = std::fs::rename(&temporary, &path);
        }
    }

    fn put_back(step: &Value) -> std::io::Result<bool> {
        let (kept, where_) = (step["kept"].as_str().unwrap_or(""), step["where"].as_str().unwrap_or(""));
        if kept.is_empty() || where_.is_empty() || !Path::new(kept).exists() || std::fs::symlink_metadata(where_).is_ok() {
            return Ok(false);
        }
        std::fs::set_permissions(kept, std::fs::Permissions::from_mode(0o600))?;
        if let Some(parent) = Path::new(where_).parent() {
            std::fs::create_dir_all(parent)?;
        }
        Self::carry(Path::new(kept), Path::new(where_))?;
        std::fs::set_permissions(where_, std::fs::Permissions::from_mode(step["mode"].as_u64().unwrap_or(0o644) as u32))?;
        let name = std::ffi::CString::new(where_).map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
        if unsafe { libc::chown(name.as_ptr(), step["uid"].as_u64().unwrap_or(0) as libc::uid_t, step["gid"].as_u64().unwrap_or(0) as libc::gid_t) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(true)
    }

    fn uncomment(key: &str, where_: &str) -> std::io::Result<Vec<u8>> {
        let mark = format!("{DISABLED_MARK}{key}: ").into_bytes();
        let raw = std::fs::read(where_)?;
        let lines: Vec<&[u8]> = raw.split(|byte| *byte == b'\n').map(|line| line.strip_prefix(mark.as_slice()).unwrap_or(line)).collect();
        Ok(lines.join(&b'\n'))
    }

    /// Put back everything cleaned under this case. Returns (put back, could not be put back).
    pub fn restore(&self, key: &str, now: f64) -> (usize, usize) {
        if !is_key(key) {
            return (0, 0);
        }
        let path = self.records().join(format!("{key}.json"));
        let Some(steps) = std::fs::read(&path).ok().and_then(|raw| serde_json::from_slice::<Value>(&raw).ok()).and_then(|value| value["steps"].as_array().cloned()) else { return (0, 0) };
        let (mut back, mut left, mut reload): (usize, Vec<Value>, bool) = (0, Vec::new(), false);
        let mut allowed: Vec<(String, BTreeSet<String>)> = Vec::new();
        for step in steps.iter().rev() {
            let kind = step["do"].as_str().unwrap_or("");
            let where_ = step["where"].as_str().unwrap_or("").to_string();
            let result: std::io::Result<bool> = (|| {
                if (kind == "moved" || kind == "commented") && step["kind"] != "program file" {
                    // What is about to be put back, as the startup watch will see it: remembered so it is left alone.
                    let body = if kind == "moved" {
                        let kept = step["kept"].as_str().unwrap_or("");
                        if Path::new(kept).exists() {
                            std::fs::set_permissions(kept, std::fs::Permissions::from_mode(0o600))?; // it was locked in quarantine
                        }
                        let mut body = std::fs::read(kept)?;
                        body.truncate(MAX_ENTRY_BYTES as usize);
                        body
                    } else {
                        let mut body = std::fs::read(&where_)?;
                        body.truncate(MAX_ENTRY_BYTES as usize);
                        let mark = format!("{DISABLED_MARK}{key}: ").into_bytes();
                        body.split(|byte| *byte == b'\n').map(|line| line.strip_prefix(mark.as_slice()).unwrap_or(line)).collect::<Vec<_>>().join(&b'\n')
                    };
                    let found: BTreeSet<String> = marks(&body).into_iter().map(|(mark, _)| mark).collect();
                    match allowed.iter_mut().find(|(name, _)| *name == where_) {
                        Some(entry) => entry.1.extend(found),
                        None => allowed.push((where_.clone(), found)),
                    }
                }
                match kind {
                    "moved" => {
                        let done = Self::put_back(step)?;
                        reload = reload || (done && where_.contains("systemd"));
                        Ok(done)
                    }
                    "commented" => {
                        let body = Self::uncomment(key, &where_)?;
                        let mut handle = std::fs::OpenOptions::new().write(true).open(&where_)?;
                        handle.write_all(&body)?;
                        handle.set_len(body.len() as u64)?;
                        Ok(true)
                    }
                    _ => Ok(false),
                }
            })();
            if kind == "review" || kind == "failed" {
                continue; // these changed nothing
            }
            if matches!(result, Ok(true)) {
                back += 1;
            } else {
                left.push(step.clone());
            }
        }
        if reload && self.system == "linux" && self.root == Path::new("/") {
            quiet(&["systemctl", "daemon-reload"]);
        }
        if !allowed.is_empty() {
            let file = self.directory.join(ALLOWED_FILE);
            let mut old: Map<String, Value> = std::fs::read(&file).ok().and_then(|raw| serde_json::from_slice::<Value>(&raw).ok()).and_then(|value| value.as_object().cloned()).unwrap_or_default();
            for (name, found) in allowed {
                let mut all: BTreeSet<String> = old.get(&name).and_then(Value::as_array).map(|list| list.iter().filter_map(|item| item.as_str().map(str::to_string)).collect()).unwrap_or_default();
                all.extend(found);
                let kept: Vec<String> = all.into_iter().collect();
                old.insert(name, json!(kept[kept.len().saturating_sub(2000)..]));
            }
            let _ = std::fs::write(&file, Value::Object(old).to_string());
        }
        if left.is_empty() {
            let _ = std::fs::remove_file(&path);
            let _ = std::fs::remove_dir_all(self.quarantine().join(key));
        } else {
            left.reverse();
            let _ = std::fs::write(&path, json!({"at": now.trunc() as i64, "steps": left}).to_string());
        }
        (back, steps.iter().filter(|step| step["do"] != "review" && step["do"] != "failed").count() - back)
    }

    /// Case keys that have something in quarantine or switched off.
    pub fn cleaned(&self) -> Vec<String> {
        let mut found: Vec<String> = sorted_entries(&self.records(), usize::MAX).unwrap_or_default().into_iter()
            .filter(|entry| entry.extension().is_some_and(|extension| extension == "json")).filter_map(|entry| entry.file_stem().map(|stem| stem.to_string_lossy().into_owned())).collect();
        found.sort();
        found
    }
}

/// One startup entry that appeared since the last look.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Appeared {
    pub kind: String,
    pub where_: String,
    /// True when the whole file is new; false when lines were added to a file that was already there.
    pub whole: bool,
    pub lines: Vec<Vec<u8>>,
}

/// Notices a startup entry the moment one appears, whoever wrote it. Each startup place is remembered as marks of
/// its lines, never the lines themselves; a line or file that was not there before is handed back to be judged.
pub struct StartupWatch {
    lister: Cleaner,
    path: PathBuf,
    known: Map<String, Value>,
    first: bool,
}

impl StartupWatch {
    pub fn new(system: &str, directory: &Path, root: Option<&Path>) -> StartupWatch {
        let path = directory.join(STARTUP_FILE);
        let known = std::fs::read(&path).ok().and_then(|raw| serde_json::from_slice::<Value>(&raw).ok());
        let first = known.is_none(); // first run: what is there now is the starting point, not news
        StartupWatch { lister: Cleaner::new(system, directory, root, false), path, known: known.and_then(|value| value.as_object().cloned()).unwrap_or_default(), first }
    }

    pub fn folders(&self) -> Vec<PathBuf> {
        self.lister.startup_folders()
    }

    /// New entries since the last look.
    pub fn poll(&mut self) -> Vec<Appeared> {
        let (mut found, mut changed) = (Vec::new(), false);
        let allowed: Map<String, Value> = std::fs::read(self.path.with_file_name(ALLOWED_FILE)).ok().and_then(|raw| serde_json::from_slice::<Value>(&raw).ok()).and_then(|value| value.as_object().cloned()).unwrap_or_default();
        let gone: Vec<String> = self.known.keys().filter(|name| std::fs::symlink_metadata(name).is_err()).cloned().collect();
        for name in gone {
            self.known.remove(&name); // gone: if it comes back, that is news
            changed = true;
        }
        for (kind, entry, whole) in self.lister.places() {
            let name = text(&entry);
            let Ok(status) = std::fs::metadata(&entry) else { continue };
            let signature = json!([status.mtime() as i128 * 1_000_000_000 + status.mtime_nsec() as i128, status.len()]);
            let old = self.known.get(&name).cloned();
            if old.as_ref().is_some_and(|old| old["sig"] == signature) || status.len() > MAX_ENTRY_BYTES {
                continue;
            }
            let Ok(body) = std::fs::read(&entry) else { continue };
            let now = marks(&body);
            let seen: BTreeSet<&str> = old.as_ref().and_then(|old| old["lines"].as_array()).map(|list| list.iter().filter_map(Value::as_str).collect()).unwrap_or_default();
            let let_be: BTreeSet<&str> = allowed.get(&name).and_then(Value::as_array).map(|list| list.iter().filter_map(Value::as_str).collect()).unwrap_or_default();
            // An entry put back by `restore` was put back on purpose: it is not news a second time. Anything else
            // that appears is, even a line that was here once before and was removed.
            let new: Vec<Vec<u8>> = now.iter().filter(|(mark, _)| !seen.contains(mark.as_str()) && !let_be.contains(mark.as_str())).map(|(_, line)| line.clone()).take(20).collect();
            let was_empty = old.as_ref().map(|old| old["lines"].as_array().is_none_or(|list| list.is_empty())).unwrap_or(true);
            let mut all: Vec<&str> = now.iter().map(|(mark, _)| mark.as_str()).collect();
            all.sort_unstable();
            self.known.insert(name.clone(), json!({"sig": signature, "lines": all}));
            changed = true;
            // The keys an account already had when this agent first read them are its starting point: an agent
            // that learns to read this place in a newer version must not take every old key for a new one.
            let settled = kind == "sign-in key" && old.is_none() && std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).is_ok_and(|now| now.as_secs() as i64 - status.mtime() > 120);
            if !new.is_empty() && !self.first && !settled {
                // A file that was not there, or was there only as an empty file a moment ago, is new as a whole.
                found.push(Appeared { kind: kind.to_string(), where_: name, whole: whole && was_empty, lines: new });
            }
        }
        if changed || self.first {
            if let Some(parent) = self.path.parent() {
                let _ = Cleaner::make_private(parent);
            }
            let temporary = self.path.with_extension("tmp");
            if std::fs::write(&temporary, Value::Object(self.known.clone()).to_string()).is_ok() {
                let _ = std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o600));
                let _ = std::fs::rename(&temporary, &self.path);
            }
        }
        self.first = false;
        found
    }
}
