//! Places that would start a program again. Read-only: it says where, never what the file contains.
//! Asked after a look, outside the watcher's lock.

use crate::score::clean;
use serde_json::{json, Value};

#[cfg(windows)]
pub fn find(path: &str) -> Vec<Value> {
    if path.len() < 4 {
        return Vec::new();
    }
    let script = format!("$ErrorActionPreference='Stop'; [Console]::OutputEncoding=[Text.UTF8Encoding]::new(); $p='{}'; $o=@(); \
        foreach($k in 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run','HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'){{ $i=Get-ItemProperty -Path $k -ErrorAction SilentlyContinue; if($i){{ foreach($n in $i.PSObject.Properties){{ if([string]$n.Value -like ('*'+$p+'*')){{ $o+=[pscustomobject]@{{Kind='startup entry';Where=($k+' : '+$n.Name)}} }} }} }} }}; \
        foreach($t in @(Get-ScheduledTask -ErrorAction SilentlyContinue)){{ foreach($a in @($t.Actions)){{ if(([string]$a.Execute+' '+[string]$a.Arguments) -like ('*'+$p+'*')){{ $o+=[pscustomobject]@{{Kind='scheduled task';Where=($t.TaskPath+$t.TaskName)}} }} }} }}; @($o | Select-Object -First 6) | ConvertTo-Json -Compress", path.replace('\'', "''"));
    let raw = crate::tool::run(&["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", &script], None, std::time::Duration::from_secs(60)).unwrap_or_default();
    let rows = match serde_json::from_str::<Value>(raw.trim_start_matches('\u{feff}')) {
        Ok(Value::Array(list)) => list,
        Ok(value) if value.is_object() => vec![value],
        _ => Vec::new(),
    };
    rows.iter().filter_map(|row| match (row["Kind"].as_str(), row["Where"].as_str()) {
        (Some(kind), Some(place)) if !kind.is_empty() && !place.is_empty() => Some(json!({"kind": clean(kind, 40), "where": clean(place, 200)})),
        _ => None,
    }).take(6).collect()
}

#[cfg(not(windows))]
pub fn find(path: &str) -> Vec<Value> {
    use std::path::{Path, PathBuf};
    if path.len() < 4 {
        return Vec::new();
    }
    let home = PathBuf::from(std::env::var("HOME").ok().filter(|home| !home.is_empty()).unwrap_or_else(|| "/root".into()));
    let places: [(&str, PathBuf); 8] = [
        ("startup service", PathBuf::from("/etc/systemd/system")), ("startup service", home.join(".config/systemd/user")), ("scheduled job", PathBuf::from("/etc/cron.d")),
        ("scheduled job", PathBuf::from("/var/spool/cron/crontabs")), ("login item", home.join(".config/autostart")), ("login item", home.join("Library/LaunchAgents")),
        ("startup service", PathBuf::from("/Library/LaunchDaemons")), ("login item", PathBuf::from("/Library/LaunchAgents")),
    ];
    let mut files: Vec<(&str, PathBuf)> = Vec::new();
    for (kind, folder) in &places {
        let mut entries: Vec<PathBuf> = std::fs::read_dir(folder).map(|entries| entries.flatten().map(|entry| entry.path()).collect()).unwrap_or_default();
        entries.sort();
        files.extend(entries.into_iter().take(200).filter(|entry| entry.is_file()).map(|entry| (*kind, entry)));
    }
    files.extend([".bashrc", ".profile", ".bash_profile", ".zshrc"].iter().map(|name| ("shell startup file", home.join(name))));
    files.push(("scheduled job", Path::new("/etc/crontab").to_path_buf()));
    let needle = path.as_bytes();
    let mut found = Vec::new();
    for (kind, entry) in files {
        if !std::fs::metadata(&entry).is_ok_and(|meta| meta.len() <= 262_144) {
            continue;
        }
        let Ok(data) = std::fs::read(&entry) else { continue };
        if data.windows(needle.len()).any(|part| part == needle) {
            found.push(json!({"kind": kind, "where": clean(&entry.to_string_lossy(), 200)}));
            if found.len() >= 6 {
                break;
            }
        }
    }
    found
}
