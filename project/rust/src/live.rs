//! The real machine: the Linux sensor the watcher looks through, and the hands it acts with.
//!
//! The slow questions (which sockets exist, which programs listen inside containers) are asked by `refresh`,
//! outside the watcher's lock, so a responder never waits behind them.

#![cfg(target_os = "linux")]

use crate::feed::ExecFeed;
use crate::linux::{LinuxSensor, Snap};
use crate::notify::exec_notify;
pub use crate::notify::startup_signal;
use crate::parse::{listening_pids, parse_ss, Conn, Proc};
use crate::respond;
pub use crate::tool::{run, Looked, Shared};
use crate::watch::{Hands, Sensor};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::mpsc::Sender;
use std::time::Duration;

pub const SYSTEM: &str = "linux";
pub type Live = LiveLinux;

/// The sensor a full look works through.
pub fn sensor(shared: Shared) -> Live {
    LiveLinux::new(Path::new("/proc"), shared)
}

/// Ask the machine what is running and connected.
pub fn refresh_now(shared: &Shared) {
    refresh(shared, Path::new("/proc"));
}

/// Only what is running: for the look that follows a stop, which needs no new list of connections.
pub fn refresh_processes(shared: &Shared) {
    let procs = LinuxSensor::new(Path::new("/proc")).processes();
    if let Ok(mut looked) = shared.lock() {
        looked.procs = procs;
    }
}

/// What is asked on threads of its own: which programs listen inside containers.
pub fn background(shared: &Shared) {
    watch_elsewhere(shared.clone(), Path::new("/proc"));
}

/// How this machine tells the agent a program has started: the kernel's process feed; where that cannot be
/// matched to processes (a container, WSL) or is permitted but says nothing, notices by file; where neither
/// works, a look for new processes several times a second.
pub struct Feeds {
    feed: Option<ExecFeed>,
    by_file: bool,
    poller: Option<LinuxSensor>,
    starts: Sender<Snap>,
    open: bool,
}

impl Feeds {
    pub fn start(starts: Sender<Snap>) -> Feeds {
        let feed = ExecFeed::open(Path::new("/proc")).ok();
        Feeds { open: feed.is_some(), feed, by_file: false, poller: None, starts }
    }

    /// True while the system itself reports program starts.
    pub fn open(&self) -> bool {
        self.open
    }

    /// True when the kernel's own process feed is open (what the service is told about coverage).
    pub fn process_feed(&self) -> bool {
        self.feed.is_some()
    }

    /// How long the run loop may sleep between two calls of `pump`, in milliseconds.
    pub fn step_ms(&self) -> u64 {
        if self.poller.is_some() { 100 } else { 20 }
    }

    /// Move what was reported to the responders. Returns true when `open` changed.
    pub fn pump(&mut self) -> bool {
        let before = self.open;
        let mut silent = false;
        if let Some(feed) = &self.feed {
            while let Ok(snap) = feed.starts.try_recv() {
                let _ = self.starts.send(snap);
            }
            let heard = feed.counts().0 > 0;
            if heard && !feed.blind() {
                self.poller = None; // the feed delivers: nothing else is needed
                return false;
            }
            silent = !heard;
            if !self.by_file && feed.blind() {
                self.listen_by_file();
            }
        } else if !self.by_file {
            self.listen_by_file();
        }
        if silent && !self.by_file && self.poller.is_none() {
            self.poller = Some(LinuxSensor::new(Path::new("/proc"))); // a feed that is permitted but silent must not blind the agent
        }
        let fresh = self.poller.as_mut().map(|sensor| sensor.fresh()).unwrap_or_default();
        if silent && !self.by_file && !fresh.is_empty() {
            // Programs start and the feed said nothing about them: it does not work here.
            self.listen_by_file();
        }
        for snap in fresh {
            let _ = self.starts.send(snap);
        }
        self.open != before
    }

    fn listen_by_file(&mut self) {
        self.by_file = true;
        self.open = exec_notify(Path::new("/proc"), self.starts.clone()).is_ok();
        self.poller = if self.open { None } else { Some(LinuxSensor::new(Path::new("/proc"))) };
    }
}

/// Programs that accept connections in a network of their own: each container has one. The same question is
/// asked once in each, with the standard nsenter tool.
fn listening_elsewhere(proc: &Path) -> HashSet<u32> {
    let mut found = HashSet::new();
    let Ok(mine) = std::fs::read_link(proc.join("self/ns/net")) else { return found };
    let mut networks: Vec<(std::path::PathBuf, String)> = Vec::new();
    let Ok(entries) = std::fs::read_dir(proc) else { return found };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.bytes().all(|byte| byte.is_ascii_digit()) {
            continue;
        }
        let Ok(network) = std::fs::read_link(entry.path().join("ns/net")) else { continue };
        if network != mine && !networks.iter().any(|(known, _)| *known == network) {
            networks.push((network, name));
        }
    }
    for (_, name) in networks.into_iter().take(64) {
        let target = format!("--net={}", proc.join(&name).join("ns/net").display());
        if let Some(raw) = run(&["nsenter", &target, "ss", "-H", "-ltnp"], None, Duration::from_secs(10)) {
            found.extend(raw.lines().flat_map(|line| listening_pids(&format!("LISTEN {line}"))));
        }
    }
    found
}

/// Ask the machine what is running and connected, and keep the answers for the next look. Call this without
/// holding the watcher's lock.
pub fn refresh(shared: &Shared, proc: &Path) {
    let raw = run(&["ss", "-H", "-tanp"], None, Duration::from_secs(15)).unwrap_or_default();
    let procs = LinuxSensor::new(proc).processes();
    read_sign_ins();
    if let Ok(mut looked) = shared.lock() {
        looked.conns = parse_ss(&raw);
        looked.listening = listening_pids(&raw).union(&looked.elsewhere).copied().collect();
        looked.procs = procs;
    }
}

/// The sign-in log, read twice a minute, and the bursts found in it that the watcher has not taken yet.
fn sign_ins() -> &'static std::sync::Mutex<(crate::signin::Log, f64, Vec<crate::signin::Burst>)> {
    static CELL: std::sync::OnceLock<std::sync::Mutex<(crate::signin::Log, f64, Vec<crate::signin::Burst>)>> = std::sync::OnceLock::new();
    CELL.get_or_init(Default::default)
}

fn read_sign_ins() {
    let now = crate::agent::now();
    if let Ok(mut kept) = sign_ins().lock() {
        if now - kept.1 >= 30.0 {
            kept.1 = now;
            kept.2 = kept.0.poll(now);
        }
    }
}

/// Keep asking, every half minute and on a thread of its own, which programs listen inside containers. With many
/// containers the question takes seconds, and no look, report or responder waits for it.
pub fn watch_elsewhere(shared: Shared, proc: &Path) {
    let proc = proc.to_path_buf();
    let _ = std::thread::Builder::new().name("garrett-containers".into()).spawn(move || loop {
        let found = listening_elsewhere(&proc);
        match shared.lock() {
            Ok(mut looked) => {
                looked.listening.extend(found.iter().copied());
                looked.elsewhere = found;
            }
            Err(_) => return,
        }
        std::thread::sleep(Duration::from_secs(30));
    });
}

pub struct LiveLinux {
    sensor: LinuxSensor,
    shared: Shared,
    ticks_per_second: f64,
}

impl LiveLinux {
    pub fn new(proc: &Path, shared: Shared) -> LiveLinux {
        let ticks = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
        LiveLinux { sensor: LinuxSensor::new(proc), shared, ticks_per_second: if ticks > 0 { ticks as f64 } else { 100.0 } }
    }
}

impl Sensor for LiveLinux {
    fn system(&self) -> &str {
        "linux"
    }
    fn processes(&mut self) -> Vec<Proc> {
        self.shared.lock().map(|looked| looked.procs.clone()).unwrap_or_default()
    }
    fn running_now(&mut self) -> Vec<Proc> {
        self.sensor.processes()
    }
    fn connections(&mut self) -> Vec<Conn> {
        self.shared.lock().map(|looked| looked.conns.clone()).unwrap_or_default()
    }
    fn command_lines(&mut self, pids: &[u32]) -> HashMap<u32, String> {
        self.sensor.command_lines(pids).into_iter().collect()
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
    fn sign_ins(&mut self) -> Vec<crate::signin::Burst> {
        sign_ins().lock().map(|mut kept| std::mem::take(&mut kept.2)).unwrap_or_default()
    }
    fn lived_ms(&mut self, proc: &Proc) -> Option<f64> {
        let mut now: libc::timespec = unsafe { std::mem::zeroed() };
        if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut now) } != 0 {
            return None;
        }
        let up = now.tv_sec as f64 + now.tv_nsec as f64 / 1e9;
        Some(((up - proc.started as f64 / self.ticks_per_second) * 1000.0).clamp(0.0, 99999.0))
    }
    fn mount_space(&mut self, pid: u32) -> Option<String> {
        std::fs::read_link(self.sensor.proc.join(pid.to_string()).join("ns/mnt")).ok().map(|space| space.to_string_lossy().into_owned())
    }
}

/// Freeze, release and end with signals; refuse addresses with one nftables table of our own.
#[derive(Default)]
pub struct RealHands;

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
    /// One table, rewritten whole, so removing it removes everything this agent did.
    fn block(&mut self, addresses: &[String]) -> Option<bool> {
        Some(block(addresses))
    }
}

/// Refuse traffic to and from exactly these addresses, replacing whatever was refused before. An empty list
/// removes the table.
pub fn block(addresses: &[String]) -> bool {
    let mut script = String::from("table inet garrett\ndelete table inet garrett\n");
    let v4: Vec<&str> = addresses.iter().filter(|address| !address.contains(':')).map(String::as_str).collect();
    let v6: Vec<&str> = addresses.iter().filter(|address| address.contains(':')).map(String::as_str).collect();
    if !addresses.is_empty() {
        let families = [("4", "ipv4_addr", "ip", &v4), ("6", "ipv6_addr", "ip6", &v6)];
        script.push_str("table inet garrett {\n");
        for (tag, kind, _, items) in families.iter().filter(|family| !family.3.is_empty()) {
            script.push_str(&format!("  set bad{tag} {{ type {kind}; elements = {{ {} }} }}\n", items.join(", ")));
        }
        for (chain, hook, sides) in [("out", "output", vec!["daddr"]), ("in", "input", vec!["saddr"]), ("through", "forward", vec!["daddr", "saddr"])] {
            script.push_str(&format!("  chain {chain} {{ type filter hook {hook} priority -10;\n"));
            for (tag, _, word, _) in families.iter().filter(|family| !family.3.is_empty()) {
                for side in &sides {
                    script.push_str(&format!("    {word} {side} @bad{tag} drop\n"));
                }
            }
            script.push_str("  }\n");
        }
        script.push_str("}\n");
    }
    run(&["nft", "-f", "-"], Some(script.as_bytes()), Duration::from_secs(15)).is_some()
}
