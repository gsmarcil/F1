//! macOS: what is running (ps), what is connected (lsof), a watch for program starts, and the hands.
//!
//! macOS gives a program no notice of process starts without a system extension, so the agent asks for the list
//! of running programs many times a second (one cheap call) and reads only the ones that were not there before.

#![cfg(target_os = "macos")]

use crate::linux::Snap;
use crate::parse::{parse_lsof, parse_ps, Conn, Proc};
use crate::respond;
use crate::tool::{run, watch_starts};
pub use crate::tool::{Looked, Shared};
use crate::watch::{Hands, Sensor};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::mpsc::Sender;
use std::time::Duration;

pub const SYSTEM: &str = "macos";

extern "C" {
    fn proc_listallpids(buffer: *mut libc::c_void, size: libc::c_int) -> libc::c_int;
    fn proc_pidpath(pid: libc::c_int, buffer: *mut libc::c_void, size: u32) -> libc::c_int;
    fn proc_pidinfo(pid: libc::c_int, flavor: libc::c_int, argument: u64, buffer: *mut libc::c_void, size: libc::c_int) -> libc::c_int;
    fn sysctl(name: *mut libc::c_int, length: libc::c_uint, old: *mut libc::c_void, old_size: *mut libc::size_t, new: *mut libc::c_void, new_size: libc::size_t) -> libc::c_int;
}

fn base(path: &str) -> String {
    path.rsplit('/').next().unwrap_or("").to_string()
}

/// Every running process id, in one call.
pub fn pids() -> HashSet<u32> {
    let mut table = [0 as libc::c_int; 8192];
    let count = unsafe { proc_listallpids(table.as_mut_ptr() as *mut libc::c_void, std::mem::size_of_val(&table) as libc::c_int) };
    table[..count.clamp(0, 8192) as usize].iter().filter(|pid| **pid > 0).map(|pid| *pid as u32).collect()
}

fn path_of(pid: u32) -> Option<String> {
    let mut buffer = [0u8; 4096];
    let length = unsafe { proc_pidpath(pid as libc::c_int, buffer.as_mut_ptr() as *mut libc::c_void, buffer.len() as u32) };
    (length > 0).then(|| String::from_utf8_lossy(&buffer[..(length as usize).min(buffer.len())]).into_owned())
}

/// One program that has just started: who it is, who started it, and its command line.
pub fn snapshot(pid: u32) -> Option<Snap> {
    let path = path_of(pid)?;
    // struct proc_bsdinfo is 136 bytes; the parent's id is its fifth 32-bit field.
    let mut info = [0u8; 136];
    let got = unsafe { proc_pidinfo(pid as libc::c_int, 3, 0, info.as_mut_ptr() as *mut libc::c_void, 136) };
    let parent = if got == 136 { u32::from_ne_bytes([info[16], info[17], info[18], info[19]]) } else { 0 };
    let above = if parent > 1 { path_of(parent).map(|path| base(&path)).unwrap_or_default() } else { String::new() };
    // The arguments as the kernel holds them: a count, the program path, padding, then each argument.
    let mut words = String::new();
    let mut raw = vec![0u8; 65536];
    let mut size: libc::size_t = raw.len();
    let mut name = [1 as libc::c_int, 49, pid as libc::c_int]; // CTL_KERN, KERN_PROCARGS2
    if unsafe { sysctl(name.as_mut_ptr(), 3, raw.as_mut_ptr() as *mut libc::c_void, &mut size, std::ptr::null_mut(), 0) } == 0 && size > 8 && size <= raw.len() {
        let count = i32::from_ne_bytes([raw[0], raw[1], raw[2], raw[3]]);
        let rest = &raw[4..size];
        if let (Some(end), true) = (rest.iter().position(|byte| *byte == 0), count > 0 && count < 4096) {
            let after = &rest[end + 1..];
            let from = after.iter().position(|byte| *byte != 0).unwrap_or(after.len());
            let joined = after[from..].split(|byte| *byte == 0).take(count as usize).map(|part| String::from_utf8_lossy(part).into_owned()).collect::<Vec<_>>().join(" ");
            words = joined.chars().take(4096).collect();
        }
    }
    // Identity matches what `ps` gives the full looks: no start time is known there either.
    Some(Snap { proc: Proc { pid, ppid: parent, name: base(&path), path, started: 0 }, cmdline: words, parent: above, jumped: false, handed: false })
}

/// Ask the machine what is running and connected, and keep the answers for the next look.
pub fn refresh_now(shared: &Shared) {
    let procs = parse_ps(&run(&["/bin/ps", "-axo", "pid=,ppid=,comm="], None, Duration::from_secs(15)).unwrap_or_default());
    let raw = run(&["/usr/sbin/lsof", "-nP", "-iTCP", "-F", "pcnT"], None, Duration::from_secs(20)).unwrap_or_default();
    // Which programs accept connections: a shell one of them starts is judged like a shell under a web server.
    let (mut listening, mut owner) = (HashSet::new(), 0u32);
    for line in raw.lines() {
        if let Some(number) = line.strip_prefix('p').filter(|rest| !rest.is_empty() && rest.bytes().all(|byte| byte.is_ascii_digit())) {
            owner = number.parse().unwrap_or(0);
        } else if line == "TST=LISTEN" && owner > 0 {
            listening.insert(owner);
        }
    }
    if let Ok(mut looked) = shared.lock() {
        looked.procs = procs;
        looked.conns = parse_lsof(&raw);
        looked.listening = listening;
    }
}

/// Only what is running: for the look that follows a stop, which needs no new list of connections.
pub fn refresh_processes(shared: &Shared) {
    let procs = parse_ps(&run(&["/bin/ps", "-axo", "pid=,ppid=,comm="], None, Duration::from_secs(15)).unwrap_or_default());
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
    /// What is running this instant, by the same identity `ps` gives (no start time).
    fn running_now(&mut self) -> Vec<Proc> {
        let mut found: Vec<Proc> = pids().into_iter().filter_map(|pid| snapshot(pid).map(|snap| snap.proc)).collect();
        found.sort_by_key(|proc| proc.pid);
        found
    }
    fn connections(&mut self) -> Vec<Conn> {
        self.shared.lock().map(|looked| looked.conns.clone()).unwrap_or_default()
    }
    fn command_lines(&mut self, pids: &[u32]) -> HashMap<u32, String> {
        let mut found = HashMap::new();
        for pid in pids.iter().take(8) {
            if let Some(raw) = run(&["/bin/ps", "-o", "args=", "-p", &pid.to_string()], None, Duration::from_secs(10)).filter(|raw| !raw.is_empty()) {
                found.insert(*pid, raw.chars().take(4096).collect());
            }
        }
        found
    }
    fn file_age(&mut self, path: &str, now: f64) -> Option<f64> {
        use std::os::unix::fs::MetadataExt;
        if path.is_empty() {
            return None;
        }
        std::fs::metadata(path).ok().map(|meta| (now - meta.ctime() as f64).trunc().max(0.0))
    }
    fn listening(&self) -> HashSet<u32> {
        self.shared.lock().map(|looked| looked.listening.clone()).unwrap_or_default()
    }
}

/// The watch for program starts. It only looks; nothing waits on it.
pub struct Feeds;

impl Feeds {
    pub fn start(starts: Sender<Snap>) -> Feeds {
        watch_starts(pids, snapshot, true, starts);
        Feeds
    }

    pub fn open(&self) -> bool {
        true
    }

    /// The kernel's own process feed: there is none here.
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

/// Freeze, release and end with signals; refuse addresses with one blackhole host route each.
#[derive(Default)]
pub struct RealHands;

/// The routes this agent has added, whichever of its hands added them: one memory for the whole process, so any
/// of them can take a route away again.
fn routes() -> &'static std::sync::Mutex<HashSet<String>> {
    static CELL: std::sync::OnceLock<std::sync::Mutex<HashSet<String>>> = std::sync::OnceLock::new();
    CELL.get_or_init(Default::default)
}

impl Hands for RealHands {
    fn suspend(&mut self, pid: u32) -> bool {
        respond::suspend(pid)
    }
    fn resume(&mut self, pid: u32) -> bool {
        respond::resume(pid)
    }
    fn kill(&mut self, pid: u32) -> bool {
        respond::kill(pid)
    }
    /// A blackhole host route per address: nothing sent to it leaves the machine, so no connection in either
    /// direction can complete. Routes are ours to delete and do not survive a restart.
    fn block(&mut self, addresses: &[String]) -> Option<bool> {
        let wanted: HashSet<String> = addresses.iter().cloned().collect();
        let mut done = true;
        let Ok(mut held) = routes().lock() else { return Some(false) };
        let mut gone: Vec<String> = held.difference(&wanted).cloned().collect();
        gone.sort();
        for address in gone {
            let mut arguments = vec!["route", "-n", "delete"];
            if address.contains(':') {
                arguments.push("-inet6");
            }
            arguments.extend(["-host", address.as_str()]);
            run(&arguments, None, Duration::from_secs(15));
            held.remove(&address);
        }
        let mut new: Vec<String> = wanted.difference(&held).cloned().collect();
        new.sort();
        for address in new {
            let mut arguments = vec!["route", "-n", "add"];
            if address.contains(':') {
                arguments.push("-inet6");
            }
            arguments.extend(["-host", address.as_str(), if address.contains(':') { "::1" } else { "127.0.0.1" }, "-blackhole"]);
            if run(&arguments, None, Duration::from_secs(15)).is_some() {
                held.insert(address);
            } else {
                done = false;
            }
        }
        Some(done)
    }
}
