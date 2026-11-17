//! Windows: process and TCP tables straight from the Windows API (no child process per sample), a watch for
//! program starts, the hands, and the lookups only PowerShell can answer (signatures, Defender's history, the
//! DNS cache, the Security log).
//!
//! The PowerShell lookups take a second or more, so they are asked while a look is being prepared, outside the
//! watcher's lock, and the sensor answers from what was found: a responder never waits behind them.

#![cfg(windows)]

use crate::linux::Snap;
use crate::parse::{Conn, Proc};
use crate::score::{clean, EVENT_SIGNALS};
use crate::tool::{run, watch_starts};
pub use crate::tool::{Looked, Shared};
use crate::watch::{Activity, Found, Hands, Sensor};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::ffi::c_void;
use std::path::PathBuf;
use std::sync::mpsc::Sender;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

pub const SYSTEM: &str = "windows";

type Handle = *mut c_void;

#[repr(C)]
struct Entry {
    size: u32,
    usage: u32,
    pid: u32,
    heap: usize,
    module: u32,
    threads: u32,
    parent: u32,
    priority: i32,
    flags: u32,
    name: [u16; 260],
}

#[link(name = "kernel32")]
extern "system" {
    fn CreateToolhelp32Snapshot(flags: u32, pid: u32) -> Handle;
    fn Process32FirstW(snapshot: Handle, entry: *mut Entry) -> i32;
    fn Process32NextW(snapshot: Handle, entry: *mut Entry) -> i32;
    fn OpenProcess(access: u32, inherit: i32, pid: u32) -> Handle;
    fn QueryFullProcessImageNameW(process: Handle, flags: u32, name: *mut u16, size: *mut u32) -> i32;
    fn GetProcessTimes(process: Handle, created: *mut u64, exited: *mut u64, kernel: *mut u64, user: *mut u64) -> i32;
    fn CloseHandle(handle: Handle) -> i32;
    fn K32EnumProcesses(table: *mut u32, bytes: u32, used: *mut u32) -> i32;
    fn TerminateProcess(process: Handle, code: u32) -> i32;
}

#[link(name = "ntdll")]
extern "system" {
    fn NtQueryInformationProcess(process: Handle, class: i32, out: *mut c_void, size: u32, used: *mut u32) -> i32;
    fn NtSuspendProcess(process: Handle) -> i32;
    fn NtResumeProcess(process: Handle) -> i32;
}

#[link(name = "iphlpapi")]
extern "system" {
    fn GetExtendedTcpTable(table: *mut c_void, size: *mut u32, sorted: i32, family: u32, class: i32, reserved: u32) -> u32;
}

#[link(name = "advapi32")]
extern "system" {
    fn OpenProcessToken(process: Handle, access: u32, token: *mut Handle) -> i32;
    fn GetTokenInformation(token: Handle, class: i32, out: *mut c_void, size: u32, used: *mut u32) -> i32;
}

#[link(name = "shell32")]
extern "system" {
    fn IsUserAnAdmin() -> i32;
}

/// True when this agent runs as an administrator.
pub fn privileged() -> bool {
    unsafe { IsUserAnAdmin() != 0 }
}

/// Open a process, use it, close it.
fn with<T>(pid: u32, access: u32, action: impl FnOnce(Handle) -> T) -> Option<T> {
    let handle = unsafe { OpenProcess(access, 0, pid) };
    if handle.is_null() {
        return None;
    }
    let result = action(handle);
    unsafe { CloseHandle(handle) };
    Some(result)
}

const QUERY_LIMITED: u32 = 0x1000;

fn base(path: &str) -> String {
    path.rsplit(['\\', '/']).next().unwrap_or("").to_string()
}

/// Every running process id, in one call: cheap enough to ask many times a second.
pub fn pids() -> HashSet<u32> {
    let mut table = vec![0u32; 8192];
    let mut used = 0u32;
    if unsafe { K32EnumProcesses(table.as_mut_ptr(), (table.len() * 4) as u32, &mut used) } == 0 {
        return HashSet::new();
    }
    table[..(used as usize / 4).min(table.len())].iter().copied().collect()
}

/// (the program file, when the process was created) or ("", 0) when it cannot be asked.
fn identity(pid: u32) -> (String, u64) {
    with(pid, QUERY_LIMITED, |handle| {
        let mut buffer = [0u16; 1024];
        let mut size = buffer.len() as u32;
        let path = if unsafe { QueryFullProcessImageNameW(handle, 0, buffer.as_mut_ptr(), &mut size) } != 0 { String::from_utf16_lossy(&buffer[..(size as usize).min(buffer.len())]) } else { String::new() };
        let (mut created, mut exited, mut kernel, mut user) = (0u64, 0u64, 0u64, 0u64);
        let started = if unsafe { GetProcessTimes(handle, &mut created, &mut exited, &mut kernel, &mut user) } != 0 { created } else { 0 };
        (path, started)
    }).unwrap_or_default()
}

/// ProcessCommandLineInformation: instant, and needs only the limited query right.
fn command_line(pid: u32) -> Option<String> {
    with(pid, QUERY_LIMITED, |handle| {
        let mut size = 0u32;
        unsafe { NtQueryInformationProcess(handle, 60, std::ptr::null_mut(), 0, &mut size) };
        if size == 0 || size > 131072 {
            return None;
        }
        // Eight-byte units, so the pointer inside the answer is aligned.
        let mut buffer = vec![0u64; (size as usize).div_ceil(8) + 1];
        if unsafe { NtQueryInformationProcess(handle, 60, buffer.as_mut_ptr() as *mut c_void, size, &mut size) } != 0 {
            return None;
        }
        // A UNICODE_STRING: its length in bytes, then (after padding) where its text is. The text is in this same answer.
        let bytes = buffer.len() * 8;
        let start = buffer.as_ptr() as usize;
        let length = (buffer[0] & 0xffff) as usize;
        let pointer = unsafe { *(buffer.as_ptr() as *const usize).add(1) };
        if pointer == 0 || length == 0 {
            return Some(String::new());
        }
        if pointer < start || pointer + length > start + bytes {
            return None;
        }
        let text = unsafe { std::slice::from_raw_parts(pointer as *const u16, length / 2) };
        Some(String::from_utf16_lossy(text).chars().take(4096).collect())
    }).flatten()
}

/// The account a process runs as, as the bytes of its identifier. `None` when it cannot be asked.
pub fn account(pid: u32) -> Option<Vec<u8>> {
    with(pid, QUERY_LIMITED, |handle| {
        let mut token: Handle = std::ptr::null_mut();
        if unsafe { OpenProcessToken(handle, 0x0008, &mut token) } == 0 || token.is_null() {
            return None; // TOKEN_QUERY was refused
        }
        // TOKEN_USER: a pointer to the identifier and its attributes, then the identifier itself, in this answer.
        let mut buffer = [0u64; 16];
        let mut used = 0u32;
        let read = unsafe { GetTokenInformation(token, 1, buffer.as_mut_ptr() as *mut c_void, std::mem::size_of_val(&buffer) as u32, &mut used) } != 0;
        unsafe { CloseHandle(token) };
        if !read {
            return None;
        }
        let (start, bytes) = (buffer.as_ptr() as usize, std::mem::size_of_val(&buffer));
        let pointer = unsafe { *(buffer.as_ptr() as *const usize) };
        if pointer < start || pointer + 8 > start + bytes {
            return None;
        }
        let parts = unsafe { *((pointer + 1) as *const u8) } as usize;
        let length = 8 + 4 * parts;
        if parts > 15 || pointer + length > start + bytes {
            return None;
        }
        Some(unsafe { std::slice::from_raw_parts(pointer as *const u8, length) }.to_vec())
    }).flatten()
}

/// What an account identifier is: "system" for the machine's own account, "person" for an account of the
/// machine, a domain or a cloud directory, "" for anything else (services, the network account).
pub fn account_kind(identifier: &[u8]) -> &'static str {
    const SYSTEM: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
    if identifier == SYSTEM {
        "system"
    } else if identifier.len() >= 12 && identifier[0] == 1 && identifier[2..8] == [0, 0, 0, 0, 0, 5] && identifier[8..12] == [21, 0, 0, 0] {
        "person" // S-1-5-21-...
    } else if identifier.len() >= 12 && identifier[0] == 1 && identifier[2..8] == [0, 0, 0, 0, 0, 12] && identifier[8..12] == [1, 0, 0, 0] {
        "person" // S-1-12-1-...
    } else {
        ""
    }
}

/// One program that has just started: who it is, who started it, and its command line.
pub fn snapshot(pid: u32) -> Option<Snap> {
    let (path, started) = identity(pid);
    if path.is_empty() {
        return None;
    }
    // PROCESS_BASIC_INFORMATION: six pointer-sized fields, the last is the parent's id.
    let parent = with(pid, QUERY_LIMITED, |handle| {
        let mut basic = [0usize; 6];
        if unsafe { NtQueryInformationProcess(handle, 0, basic.as_mut_ptr() as *mut c_void, std::mem::size_of_val(&basic) as u32, std::ptr::null_mut()) } == 0 { basic[5] as u32 } else { 0 }
    }).unwrap_or(0);
    let (above_path, above_started) = if parent > 4 { identity(parent) } else { (String::new(), 0) };
    let above = base(&above_path);
    // A shell that runs as SYSTEM under a program of an ordinary account: nothing on Windows grants that. Asked
    // only of script hosts, and only when the parent is older than the child, so its number is really its own.
    let jumped = parent > 4 && above_started > 0 && above_started <= started && crate::score::is_script_host(&base(&path).to_lowercase())
        && account(pid).is_some_and(|own| account_kind(&own) == "system") && account(parent).is_some_and(|theirs| account_kind(&theirs) == "person");
    // A process is listed a moment before its command line can be read: asked again for up to two milliseconds.
    let mut line = command_line(pid).unwrap_or_default();
    let until = std::time::Instant::now() + Duration::from_millis(2);
    while line.is_empty() && std::time::Instant::now() < until {
        std::thread::yield_now();
        line = command_line(pid).unwrap_or_default();
    }
    Some(Snap { proc: Proc { pid, ppid: parent, name: base(&path), path, started }, cmdline: line, parent: above, jumped, handed: false })
}

fn cache() -> &'static Mutex<HashMap<u32, Proc>> {
    static CELL: OnceLock<Mutex<HashMap<u32, Proc>>> = OnceLock::new();
    CELL.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Every running process. A process already known under the same name and parent is not asked about again.
pub fn processes() -> Vec<Proc> {
    let snapshot = unsafe { CreateToolhelp32Snapshot(0x2, 0) }; // TH32CS_SNAPPROCESS
    if snapshot.is_null() || snapshot as isize == -1 {
        return Vec::new();
    }
    let Ok(mut known) = cache().lock() else { return Vec::new() };
    let mut found: HashMap<u32, Proc> = HashMap::new();
    let mut entry: Entry = unsafe { std::mem::zeroed() };
    entry.size = std::mem::size_of::<Entry>() as u32;
    let mut more = unsafe { Process32FirstW(snapshot, &mut entry) };
    while more != 0 {
        let end = entry.name.iter().position(|unit| *unit == 0).unwrap_or(entry.name.len());
        let name = String::from_utf16_lossy(&entry.name[..end]);
        let proc = match known.remove(&entry.pid).filter(|before| before.name == name && before.ppid == entry.parent) {
            Some(before) => before,
            None => {
                let (path, started) = if entry.pid > 4 { identity(entry.pid) } else { (String::new(), 0) };
                Proc { pid: entry.pid, ppid: entry.parent, name, path, started }
            }
        };
        found.insert(entry.pid, proc);
        more = unsafe { Process32NextW(snapshot, &mut entry) };
    }
    unsafe { CloseHandle(snapshot) };
    let mut list: Vec<Proc> = found.values().cloned().collect();
    list.sort_by_key(|proc| proc.pid);
    *known = found;
    list
}

fn table(family: u32) -> Vec<u8> {
    let mut size = 0u32;
    unsafe { GetExtendedTcpTable(std::ptr::null_mut(), &mut size, 0, family, 5, 0) }; // TCP_TABLE_OWNER_PID_ALL
    for _ in 0..3 {
        let mut buffer = vec![0u8; size as usize + 4096];
        size = buffer.len() as u32;
        if unsafe { GetExtendedTcpTable(buffer.as_mut_ptr() as *mut c_void, &mut size, 0, family, 5, 0) } == 0 {
            return buffer;
        }
    }
    Vec::new()
}

/// Every TCP connection with the process that owns it.
pub fn connections() -> Vec<Conn> {
    let little = |raw: &[u8], at: usize| u32::from_le_bytes([raw[at], raw[at + 1], raw[at + 2], raw[at + 3]]);
    let port = |raw: &[u8], at: usize| u16::from_be_bytes([raw[at], raw[at + 1]]) as u32;
    let mut rows: Vec<(u32, u32, u32, String, u32, String)> = Vec::new(); // (state, pid, local port, remote address, remote port, local address)
    let raw = table(2);
    let count = if raw.len() >= 4 { little(&raw, 0) as usize } else { 0 };
    for index in 0..count {
        let at = 4 + index * 24;
        if at + 24 > raw.len() {
            break;
        }
        let address = |from: usize| std::net::Ipv4Addr::new(raw[from], raw[from + 1], raw[from + 2], raw[from + 3]).to_string();
        rows.push((little(&raw, at), little(&raw, at + 20), port(&raw, at + 8), address(at + 12), port(&raw, at + 16), address(at + 4)));
    }
    let raw = table(23);
    let count = if raw.len() >= 4 { little(&raw, 0) as usize } else { 0 };
    for index in 0..count {
        let at = 4 + index * 56;
        if at + 56 > raw.len() {
            break;
        }
        let address = |from: usize| {
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(&raw[from..from + 16]);
            std::net::Ipv6Addr::from(bytes).to_string()
        };
        rows.push((little(&raw, at + 48), little(&raw, at + 52), port(&raw, at + 20), address(at + 24), port(&raw, at + 44), address(at)));
    }
    let listening: HashSet<(u32, u32)> = rows.iter().filter(|row| row.0 == 2).map(|row| (row.1, row.2)).collect();
    // 3 SYN sent, 5 established, 6-10 closing: the other side hanging up first must not hide the connection.
    rows.into_iter().filter(|row| matches!(row.0, 3 | 5 | 6 | 7 | 8 | 9 | 10))
        .map(|(_, pid, lport, raddr, rport, laddr)| Conn { pid, lport, raddr, rport, inbound: listening.contains(&(pid, lport)), laddr }).collect()
}

/// One PowerShell question whose answer is JSON: a list of objects, or nothing.
fn ps_json(script: &str, timeout: Duration) -> Vec<Value> {
    let whole = format!("$ErrorActionPreference='Stop'; [Console]::OutputEncoding=[Text.UTF8Encoding]::new(); {script}");
    let raw = run(&["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", &whole], None, timeout).unwrap_or_default();
    match serde_json::from_str::<Value>(raw.trim_start_matches('\u{feff}')) {
        Ok(Value::Array(list)) => list,
        Ok(value) if value.is_object() => vec![value],
        _ => Vec::new(),
    }
}

fn signatures(paths: &[String]) -> HashMap<String, (String, String)> {
    let quoted: Vec<String> = paths.iter().take(8).map(|path| format!("'{}'", path.replace('\'', "''"))).collect();
    let rows = ps_json(&format!("@(@({}) | ForEach-Object {{ $s=Get-AuthenticodeSignature -LiteralPath $_; [pscustomobject]@{{Path=$_;Status=[string]$s.Status;Signer=[string]$s.SignerCertificate.Subject}} }}) | ConvertTo-Json -Compress", quoted.join(",")), Duration::from_secs(60));
    let mut found = HashMap::new();
    for row in rows {
        if let Some(path) = row["Path"].as_str() {
            let state = match row["Status"].as_str() {
                Some("Valid") => "signed",
                Some("NotSigned") => "unsigned",
                _ => "untrusted",
            };
            found.insert(path.to_string(), (state.to_string(), clean(row["Signer"].as_str().unwrap_or(""), 120)));
        }
    }
    found
}

/// Windows Defender's own detection history: what the antivirus already caught on this device.
fn detections() -> Vec<Found> {
    let rows = ps_json("$n=@{}; Get-MpThreat | ForEach-Object { $n[[string]$_.ThreatID]=@([string]$_.ThreatName,[bool]$_.DidThreatExecute,[bool]$_.IsActive) }; \
        @(Get-MpThreatDetection | Select-Object -First 50 | ForEach-Object { $k=[string]$_.ThreatID; $m=$n[$k]; [pscustomobject]@{Id=[string]$_.DetectionID;Name=[string]$m[0];Executed=[bool]$m[1];Active=[bool]$m[2];\
        At=[int64]([DateTimeOffset]$_.InitialDetectionTime).ToUnixTimeSeconds();Process=[string]$_.ProcessName;Resource=[string](@($_.Resources)[0])} }) | ConvertTo-Json -Compress", Duration::from_secs(60));
    let mut found = Vec::new();
    for row in rows {
        let Some(id) = row["Id"].as_str().filter(|id| !id.is_empty()) else { continue };
        // "file:_C:\..." and the like: only the place itself is kept.
        let resource = row["Resource"].as_str().unwrap_or("");
        let letters = resource.chars().take_while(|letter| letter.is_ascii_alphabetic()).count();
        let resource = if letters >= 2 && resource[letters..].starts_with(':') { resource[letters + 1..].strip_prefix('_').unwrap_or(&resource[letters + 1..]) } else { resource };
        let name = row["Name"].as_str().filter(|name| !name.is_empty()).unwrap_or("a threat");
        found.push(Found { id: id.to_string(), name: clean(name, 120), executed: row["Executed"] == true, active: row["Active"] == true,
            at: row["At"].as_i64().unwrap_or(0) as f64, process: clean(row["Process"].as_str().unwrap_or(""), 80), resource: clean(resource, 300) });
    }
    found
}

fn names() -> HashMap<String, Vec<String>> {
    let rows = ps_json("@(Get-DnsClientCache | Select-Object -First 4000 Entry,Data) | ConvertTo-Json -Compress", Duration::from_secs(60));
    let mut found: HashMap<String, Vec<String>> = HashMap::new();
    for row in rows {
        if let (Some(entry), Some(address)) = (row["Entry"].as_str(), row["Data"].as_str().and_then(|data| data.parse::<std::net::IpAddr>().ok())) {
            let name = entry.to_lowercase().trim_matches('.').to_string();
            let list = found.entry(address.to_string()).or_default();
            if !list.contains(&name) {
                list.push(name);
            }
        }
    }
    for list in found.values_mut() {
        list.sort();
    }
    found
}

/// Per-account summaries of the Security log's directory-attack events. Empty without administrator rights.
fn directory_events() -> Vec<Activity> {
    let script = "$s=(Get-Date).AddMinutes(-6); $o=@(); \
        function Ev($id){ try { Get-WinEvent -FilterHashtable @{LogName='Security';Id=$id;StartTime=$s} -MaxEvents 2000 -ErrorAction Stop } catch { @() } }; \
        function Val($e,$n){ ([xml]$e.ToXml()).Event.EventData.Data | Where-Object { $_.Name -eq $n } | ForEach-Object { [string]$_.'#text' } | Select-Object -First 1 }; \
        $k=@{}; foreach($e in Ev 4769){ if((Val $e 'TicketEncryptionType') -eq '0x17'){ $a=Val $e 'TargetUserName'; $svc=Val $e 'ServiceName'; if($svc -and -not $svc.EndsWith('$') -and $svc -ne 'krbtgt'){ if(-not $k[$a]){$k[$a]=@{}}; $k[$a][$svc]=1 } } }; \
        foreach($a in $k.Keys){ if($k[$a].Count -ge 5){ $o+=[pscustomobject]@{Kind='kerberoast';Account=$a;Count=$k[$a].Count} } }; \
        $d=@{}; foreach($e in Ev 4662){ $p=Val $e 'Properties'; $a=Val $e 'SubjectUserName'; if($p -match '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2|1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' -and $a -and -not $a.EndsWith('$')){ $d[$a]=1+[int]$d[$a] } }; \
        foreach($a in $d.Keys){ $o+=[pscustomobject]@{Kind='dcsync';Account=$a;Count=$d[$a]} }; \
        $f=@{}; foreach($e in Ev 4625){ $a=Val $e 'TargetUserName'; $f[$a]=1+[int]$f[$a] }; foreach($a in $f.Keys){ if($f[$a] -ge 20){ $o+=[pscustomobject]@{Kind='logon_failures';Account=$a;Count=$f[$a]} } }; \
        $c=@(Ev 1102); if($c.Count){ $o+=[pscustomobject]@{Kind='log_cleared';Account=[string](([xml]$c[0].ToXml()).Event.UserData.LogFileCleared.SubjectUserName);Count=$c.Count} }; \
        $g=@{}; foreach($id in 4728,4732,4756){ foreach($e in Ev $id){ $n=Val $e 'TargetUserName'; if($n -match '^(Domain Admins|Enterprise Admins|Schema Admins|Administrators|Account Operators|Backup Operators)$'){ $a=Val $e 'SubjectUserName'; $g[$a]=1+[int]$g[$a] } } }; \
        foreach($a in $g.Keys){ $o+=[pscustomobject]@{Kind='privileged_group';Account=$a;Count=$g[$a]} }; @($o | Select-Object -First 20) | ConvertTo-Json -Compress";
    let mut found = Vec::new();
    for row in ps_json(script, Duration::from_secs(90)) {
        let (Some(kind), Some(count)) = (row["Kind"].as_str(), row["Count"].as_i64()) else { continue };
        if count > 0 && EVENT_SIGNALS.iter().any(|(known, _, _, _)| *known == kind) {
            let account = row["Account"].as_str().filter(|account| !account.is_empty()).unwrap_or("unknown account");
            found.push(Activity { kind: kind.to_string(), account: clean(account, 80), count: count.min(100000) });
        }
    }
    found
}

/// What only PowerShell can answer, asked while a look is prepared and kept for the sensor.
#[derive(Default)]
struct Slow {
    signatures: HashMap<String, (String, String)>,
    wanted: Vec<String>,
    names: HashMap<String, Vec<String>>,
    named: HashSet<String>,
    names_at: f64,
    detections: Vec<Found>,
    detections_at: f64,
    events: Vec<Activity>,
    events_at: f64,
}

fn slow() -> &'static Mutex<Slow> {
    static CELL: OnceLock<Mutex<Slow>> = OnceLock::new();
    CELL.get_or_init(|| Mutex::new(Slow::default()))
}

/// Ask the machine what is running and connected, and whatever slow question is due.
pub fn refresh_now(shared: &Shared) {
    let (procs, conns) = (processes(), connections());
    let now = crate::agent::now();
    let (wanted, want_names, want_detections, want_events) = match slow().lock() {
        Ok(mut slow) => {
            let wanted: Vec<String> = slow.wanted.drain(..).take(8).collect();
            let fresh = conns.iter().any(|conn| crate::net::is_internet(&conn.raddr) && !slow.named.contains(&conn.raddr));
            (wanted, fresh && now - slow.names_at >= 60.0, now - slow.detections_at >= 300.0, now - slow.events_at >= 60.0)
        }
        Err(_) => (Vec::new(), false, false, false),
    };
    let signed = if wanted.is_empty() { HashMap::new() } else { signatures(&wanted) };
    let named = want_names.then(names);
    let detected = want_detections.then(detections);
    let events = want_events.then(directory_events);
    if let Ok(mut slow) = slow().lock() {
        for path in wanted {
            let answer = signed.get(&path).cloned().unwrap_or_default(); // asked once, whatever the answer
            slow.signatures.insert(path, answer);
        }
        if let Some(found) = named {
            slow.names_at = now;
            slow.named = conns.iter().map(|conn| conn.raddr.clone()).collect();
            if !found.is_empty() {
                slow.names = found;
            }
        }
        if let Some(found) = detected {
            slow.detections_at = now;
            slow.detections = found;
        }
        if let Some(found) = events {
            slow.events_at = now;
            slow.events = found;
        }
    }
    if let Ok(mut looked) = shared.lock() {
        looked.procs = procs;
        looked.conns = conns;
    }
}

/// Only what is running: for the look that follows a stop, which needs no new list of connections.
pub fn refresh_processes(shared: &Shared) {
    let procs = processes();
    if let Ok(mut looked) = shared.lock() {
        looked.procs = procs;
    }
}

pub fn background(_shared: &Shared) {}

pub struct Live {
    shared: Shared,
}

pub fn sensor(shared: Shared) -> Live {
    Live { shared }
}

impl Sensor for Live {
    fn system(&self) -> &str {
        SYSTEM
    }
    fn processes(&mut self) -> Vec<Proc> {
        self.shared.lock().map(|looked| looked.procs.clone()).unwrap_or_default()
    }
    fn running_now(&mut self) -> Vec<Proc> {
        processes()
    }
    fn connections(&mut self) -> Vec<Conn> {
        self.shared.lock().map(|looked| looked.conns.clone()).unwrap_or_default()
    }
    fn command_lines(&mut self, pids: &[u32]) -> HashMap<u32, String> {
        pids.iter().take(64).filter_map(|pid| command_line(*pid).map(|line| (*pid, line))).collect()
    }
    /// Answers from what has been looked up; a file not looked up yet is asked about while the next look is prepared.
    fn signatures(&mut self, paths: &[String]) -> HashMap<String, (String, String)> {
        let Ok(mut slow) = slow().lock() else { return HashMap::new() };
        let mut found = HashMap::new();
        for path in paths {
            match slow.signatures.get(path) {
                Some(known) => {
                    found.insert(path.clone(), known.clone());
                }
                None if !slow.wanted.contains(path) && slow.wanted.len() < 64 => slow.wanted.push(path.clone()),
                None => {}
            }
        }
        found
    }
    fn signatures_later(&self) -> bool {
        true
    }
    fn names(&mut self) -> HashMap<String, Vec<String>> {
        slow().lock().map(|slow| slow.names.clone()).unwrap_or_default()
    }
    fn detections(&mut self) -> Vec<Found> {
        slow().lock().map(|slow| slow.detections.clone()).unwrap_or_default()
    }
    fn directory_events(&mut self) -> Option<Vec<Activity>> {
        Some(slow().lock().map(|slow| slow.events.clone()).unwrap_or_default())
    }
    fn file_age(&mut self, path: &str, now: f64) -> Option<f64> {
        if path.is_empty() {
            return None;
        }
        let created = std::fs::metadata(path).ok()?.created().ok()?.duration_since(std::time::UNIX_EPOCH).ok()?.as_secs_f64();
        Some((now - created).trunc().max(0.0))
    }
    fn lived_ms(&mut self, proc: &Proc) -> Option<f64> {
        if proc.started == 0 {
            return None;
        }
        // The creation time counts 100-nanosecond steps from the year 1601.
        let age = crate::agent::now() - (proc.started as f64 / 1e7 - 11_644_473_600.0);
        Some((age * 1000.0).clamp(0.0, 99999.0))
    }
}

/// The watch for program starts. It only looks; nothing waits on it.
pub struct Feeds;

impl Feeds {
    pub fn start(starts: Sender<Snap>) -> Feeds {
        watch_starts(pids, snapshot, false, starts);
        Feeds
    }

    pub fn open(&self) -> bool {
        true
    }

    /// The kernel's own process feed: not used here.
    pub fn process_feed(&self) -> bool {
        false
    }

    pub fn step_ms(&self) -> u64 {
        50
    }

    pub fn pump(&mut self) -> bool {
        false
    }
}

/// There is no instant notice of a changed startup place here: startup places are read at every look.
pub fn startup_signal(_folders: &[PathBuf], _changed: Sender<()>) -> std::io::Result<usize> {
    Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "not available on this system"))
}

/// Freeze, release and end through the Windows API; refuse addresses with two firewall rules of our own.
#[derive(Default)]
pub struct RealHands;

fn real(pid: u32) -> bool {
    pid > 4 // never the idle process or the system process
}

impl Hands for RealHands {
    fn suspend(&mut self, pid: u32) -> bool {
        real(pid) && with(pid, 0x0800, |handle| unsafe { NtSuspendProcess(handle) } == 0).unwrap_or(false) // PROCESS_SUSPEND_RESUME
    }
    fn resume(&mut self, pid: u32) -> bool {
        real(pid) && with(pid, 0x0800, |handle| unsafe { NtResumeProcess(handle) } == 0).unwrap_or(false)
    }
    fn kill(&mut self, pid: u32) -> bool {
        real(pid) && with(pid, 0x0001, |handle| unsafe { TerminateProcess(handle, 1) } != 0).unwrap_or(false) // PROCESS_TERMINATE
    }
    fn block(&mut self, addresses: &[String]) -> Option<bool> {
        let wait = Duration::from_secs(15);
        run(&["netsh", "advfirewall", "firewall", "delete", "rule", "name=Garrett fleet block"], None, wait);
        let mut done = true;
        if !addresses.is_empty() {
            let remote = format!("remoteip={}", addresses.join(","));
            for direction in ["dir=out", "dir=in"] {
                done = run(&["netsh", "advfirewall", "firewall", "add", "rule", "name=Garrett fleet block", direction, "action=block", &remote], None, wait).is_some() && done;
            }
        }
        Some(done)
    }
}
