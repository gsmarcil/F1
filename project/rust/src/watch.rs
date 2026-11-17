//! The watcher: feed it looks at the machine with `tick()`; it returns the cases that should be reported now.
//!
//! It follows programs, builds what the scorer needs to know about each, decides what becomes a case, and freezes
//! or ends a program the containment chains name. It is held to a hundred scripted events
//! (tests/fixtures/events.jsonl): the same cases must come out at every look.
//!
//! Acting at the event is here too: `on_exec` is handed each program the moment the kernel reports it, holds a
//! shell that a network-facing program started while it is judged, and ends it or lets it go; the adaptive hold
//! learns what each such program normally starts. Those are held to recorded sequences
//! (tests/fixtures/instant.jsonl).
//!
//! The startup watch, cleanup, web logs, the fleet mesh and what is kept on disk between runs are in `more`.

use crate::linux::Snap;
use crate::net::is_internet;
use crate::parse::{Conn, Proc};
use crate::score::{
    agent_marks, clean, containment_reason, is_document_parent, is_script_host, is_shell, score_process, unix_temp, user_writable, Detection, Outcome, Remote, View,
    ARCHIVE_PARENTS, BROWSERS, DIRECTORY_TOOLS, INTERPRETER_PREFIXES, LOADER_TOOLS, MAIL_PARENTS, REMOTE_SESSION_PARENTS, WEB_SERVER_PREFIXES,
};
use regex::Regex;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::OnceLock;

mod more;

pub const MAX_CASES_PER_REPORT: usize = 8;
pub const LEVELS: &[&str] = &["CLEAR", "WATCH", "SUSPECT", "HOSTILE"];
pub const SIEGE_SECONDS: f64 = 600.0;
const PLAIN_SHELLS: &[&str] = &["cmd.exe", "powershell.exe", "pwsh.exe", "conhost.exe", "sh", "bash", "dash", "zsh", "ksh"];
/// Never paused or stopped, whatever the score: the operating system, remote access to a server, container
/// runtimes and security software.
const PROTECTED_NAMES: &[&str] = &[
    "system", "registry", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe",
    "svchost.exe", "explorer.exe", "dwm.exe", "fontdrvhost.exe", "msmpeng.exe", "nissrv.exe",
    "securityhealthservice.exe", "mpdefendercoreservice.exe", "systemd", "init", "sshd", "kubelet", "containerd",
    "containerd-shim", "containerd-shim-runc-v2", "dockerd", "crio", "launchd", "kernel_task", "loginwindow",
    "windowserver",
];
/// Programs that accept connections and start shells as their ordinary work.
const LISTENER_EXEMPT: &[&str] = &["sshd", "systemd", "init", "docker", "containerd", "kubelet", "crio", "cri-o", "podman", "cron", "tmux", "screen",
    "mosh", "login", "su", "sudo", "gdm", "sddm", "xrdp", "telnetd", "in.telnetd", "inetd", "xinetd", "garrett"];

fn starts(name: &str, prefixes: &[&str]) -> bool {
    prefixes.iter().any(|prefix| name.starts_with(prefix))
}

pub(crate) fn dropped_windows() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| Regex::new(r"(?i)\\(Temp|Tmp|Downloads|Users\\Public)\\").expect("a fixed pattern"))
}

/// One antivirus detection as the sensor reports it.
#[derive(Clone, Debug, Default)]
pub struct Found {
    pub id: String,
    pub name: String,
    pub executed: bool,
    pub active: bool,
    pub at: f64,
    pub process: String,
    pub resource: String,
}

/// One account's activity in the Windows Security log.
#[derive(Clone, Debug, Default)]
pub struct Activity {
    pub kind: String,
    pub account: String,
    pub count: i64,
}

/// What the watcher asks of the machine. Each system has its own sensor; the tests have a scripted one.
pub trait Sensor {
    fn system(&self) -> &str;
    fn processes(&mut self) -> Vec<Proc>;
    /// What is running this instant, where `processes` answers from the last full look.
    fn running_now(&mut self) -> Vec<Proc> {
        self.processes()
    }
    fn connections(&mut self) -> Vec<Conn>;
    /// The command lines of these processes; one that cannot be read is left out.
    fn command_lines(&mut self, pids: &[u32]) -> HashMap<u32, String>;
    /// (state, signer) for each program file: state is "unsigned", "untrusted", "signed" or empty.
    fn signatures(&mut self, _paths: &[String]) -> HashMap<String, (String, String)> {
        HashMap::new()
    }
    /// True when `signatures` answers from what has been looked up so far and a missing answer means "not yet":
    /// the file is then asked about again at the next look instead of being left unknown for good.
    fn signatures_later(&self) -> bool {
        false
    }
    /// Names this machine knows for addresses it has talked to.
    fn names(&mut self) -> HashMap<String, Vec<String>> {
        HashMap::new()
    }
    fn detections(&mut self) -> Vec<Found> {
        Vec::new()
    }
    /// `None` where the system has no such log.
    fn directory_events(&mut self) -> Option<Vec<Activity>> {
        None
    }
    /// Addresses with a burst of failed SSH sign-ins, where the system keeps such a log.
    fn sign_ins(&mut self) -> Vec<crate::signin::Burst> {
        Vec::new()
    }
    /// Seconds since the program file appeared on this device, when that can be told.
    fn file_age(&mut self, path: &str, now: f64) -> Option<f64>;
    /// The programs that accept network connections.
    fn listening(&self) -> HashSet<u32> {
        HashSet::new()
    }
    /// How long this program has been running, in milliseconds, where the system says when it started.
    fn lived_ms(&mut self, _proc: &Proc) -> Option<f64> {
        None
    }
    /// Which file system this process lives in: a program in a container has one of its own. `None` where that
    /// cannot be told or does not apply.
    fn mount_space(&mut self, _pid: u32) -> Option<String> {
        None
    }
}

/// Freeze, release or end one process.
pub trait Hands {
    fn suspend(&mut self, pid: u32) -> bool;
    fn resume(&mut self, pid: u32) -> bool;
    fn kill(&mut self, pid: u32) -> bool;
    /// Refuse traffic to and from exactly these addresses, replacing whatever was refused before. `None` when
    /// this system has no way to do that.
    fn block(&mut self, _addresses: &[String]) -> Option<bool> {
        None
    }
}

type Identity = (u32, u64);

struct Tracked {
    proc: Proc,
    first_seen: f64,
    cmdline: Option<String>,
    signature: Option<(String, String)>,
    file_age: Option<f64>,
    parent_name: String,
    last_alive: f64,
    noted: bool,
    served: bool,
    counted: bool,
    remotes: Vec<((String, u32), BTreeSet<String>)>,
    contacts: Vec<((String, u32), Vec<f64>)>,
    inbound: Vec<(u32, Vec<(String, f64)>)>,
    seen: HashSet<(u32, String, u32)>,
    origin: String,
}

pub(crate) struct LedgerEntry {
    pub first: f64,
    pub last: f64,
    pub remotes: Vec<String>,
}

/// "pause": freeze a hostile program and wait for a person. "kill": end it at once. "decide": freeze it and let
/// the service's decision model say.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Pause,
    Decide,
    Kill,
}

pub struct Watcher<S: Sensor, H: Hands> {
    pub sensor: S,
    pub hands: Option<H>,
    salt: String,
    system_root: String,
    pub mode: Mode,
    pub policy: HashMap<String, i64>,
    pub shapes: Vec<(String, String)>,
    pub trusted: HashSet<String>,
    pub exits: Vec<String>,
    pub fleet: Vec<(String, String)>,
    pub suspects: Vec<String>,
    /// This agent and every ancestor of it: never paused or stopped.
    pub own: HashSet<u32>,
    /// This agent's own process (0 when not set). The lookups it starts itself are never followed or judged: the
    /// Windows Security-log lookup names the attacks it searches for on its own command line.
    pub myself: u32,
    tracked: Vec<Tracked>,
    known: HashSet<Identity>,
    paused: HashSet<Identity>,
    released: HashSet<Identity>,
    reported: HashMap<String, (String, f64, i64)>,
    repeats: HashMap<String, i64>,
    ledger: HashMap<String, LedgerEntry>,
    signatures: HashMap<String, (String, String)>,
    names: HashMap<String, Vec<String>>,
    names_at: f64,
    streams: Vec<(u32, Vec<(f64, String)>)>,
    listeners: HashSet<u32>,
    sieges: HashMap<u32, f64>,
    detections_seen: HashSet<String>,
    detections_at: f64,
    directory_at: f64,
    pub ticks: u64,
    /// True where program starts are seen as they happen (a kernel feed or a start watch is running).
    pub event_feed: bool,
    /// Set when a responder acted: the case should be reported now, not at the next full look.
    pub urgent: bool,
    /// What each network-facing program normally starts, as marks of the commands, never the commands.
    habits: HashMap<String, HashSet<String>>,
    /// What a responder did to a program at the event, waiting to be said with its case.
    instant: HashMap<Identity, Value>,
    more: more::More,
}

/// A program the scorer or a person may not touch because of what it is, never because of what it is called
/// while sitting where intruders drop files.
pub fn protected(proc: &Proc, own: &HashSet<u32>) -> bool {
    let name = proc.name.to_lowercase();
    if own.contains(&proc.pid) || proc.pid <= 4 || BROWSERS.contains(&name.as_str()) || is_document_parent(&name) {
        return true;
    }
    let dropped = !proc.path.is_empty() && (unix_temp().is_match(&proc.path) || dropped_windows().is_match(&proc.path));
    (PROTECTED_NAMES.contains(&name.as_str()) || starts(&name, WEB_SERVER_PREFIXES)) && !dropped
}

impl<S: Sensor, H: Hands> Watcher<S, H> {
    /// `hands` is `None` in report mode: nothing is ever touched. `system_root` is the lower-cased Windows folder
    /// with a trailing backslash.
    pub fn new(sensor: S, hands: Option<H>, salt: &str, mode: Mode, system_root: &str) -> Watcher<S, H> {
        Watcher {
            sensor, hands, salt: salt.to_string(), system_root: system_root.to_string(), mode, policy: HashMap::new(), shapes: Vec::new(),
            trusted: HashSet::new(), exits: Vec::new(), fleet: Vec::new(), suspects: Vec::new(), own: HashSet::new(), myself: 0,
            tracked: Vec::new(), known: HashSet::new(), paused: HashSet::new(), released: HashSet::new(), reported: HashMap::new(),
            repeats: HashMap::new(), ledger: HashMap::new(), signatures: HashMap::new(), names: HashMap::new(), names_at: 0.0, streams: Vec::new(),
            listeners: HashSet::new(), sieges: HashMap::new(), detections_seen: HashSet::new(), detections_at: 0.0, directory_at: 0.0, ticks: 0,
            event_feed: false, urgent: false, habits: HashMap::new(), instant: HashMap::new(), more: more::More { decide_after: 20.0, clean_up: true, ..more::More::default() },
        }
    }

    /// A command line with what changes from run to run taken out, as a mark: never the command line itself.
    pub fn shape(cmdline: &str) -> String {
        static CELL: OnceLock<Regex> = OnceLock::new();
        let joined: String = cmdline.split_whitespace().collect::<Vec<_>>().join(" ").chars().take(400).collect();
        let plain = CELL.get_or_init(|| Regex::new(r"[0-9a-fA-F]{8,}|\d+").expect("a fixed pattern")).replace_all(&joined, "0");
        Sha256::digest(plain.as_bytes()).iter().take(8).map(|byte| format!("{byte:02x}")).collect()
    }

    /// True when the program that started this was used for an attack minutes ago and this is not a command it
    /// normally starts. Only where program starts are seen as they happen, so the normal ones are known.
    fn unusual(&self, ppid: u32, parent_name: &str, cmdline: &str, now: f64) -> bool {
        if !self.event_feed || self.sieges.get(&ppid).copied().unwrap_or(0.0) <= now {
            return false;
        }
        !self.habits.get(&parent_name.to_lowercase()).is_some_and(|shapes| shapes.contains(&Self::shape(cmdline)))
    }

    /// A program has just started. A shell that a network-facing program started is held still at once, so
    /// nothing it was sent to do happens while its command line is read; then it is judged, and ended or let go.
    /// Only that narrow kind of program is ever held, and never a sign-in shell.
    pub fn on_exec(&mut self, snap: &Snap, now: f64) {
        let proc = &snap.proc;
        if self.mine(proc) {
            return;
        }
        self.escalation_case(snap, now);
        let lowered = proc.name.to_lowercase();
        let identity = (proc.pid, proc.started);
        let mut frozen = false;
        if self.hands.is_some() && self.sensor.system() != "windows" && (is_shell(&lowered) || starts(&lowered, INTERPRETER_PREFIXES))
            && (self.served(proc.ppid, &snap.parent) || starts(&snap.parent.to_lowercase(), WEB_SERVER_PREFIXES))
            && !protected(proc, &self.own) && !self.paused.contains(&identity) && !self.released.contains(&identity)
        {
            frozen = self.hands.as_mut().is_some_and(|hands| hands.suspend(proc.pid));
        }
        let held = self.instant(snap, frozen, now);
        if frozen && !held {
            if let Some(hands) = self.hands.as_mut() {
                hands.resume(proc.pid); // ordinary, or not this agent's to stop: let go at once
            }
        }
    }

    /// One responder, one program that has just started. Returns true when it stays frozen or was ended.
    fn instant(&mut self, snap: &Snap, frozen: bool, now: f64) -> bool {
        let (proc, parent, cmdline) = (&snap.proc, snap.parent.as_str(), snap.cmdline.as_str());
        let system = self.sensor.system().to_string();
        let served = self.served(proc.ppid, parent) || starts(&parent.to_lowercase(), WEB_SERVER_PREFIXES);
        let lowered = proc.name.to_lowercase();
        if system == "windows" {
            // A script host or system tool: what started it and its command line decide.
            if !is_script_host(&lowered) {
                return false;
            }
        } else if !served || !(is_shell(&lowered) || starts(&lowered, INTERPRETER_PREFIXES)) {
            return false; // everything else is judged at the next look, as before
        }
        let siege = self.unusual(proc.ppid, parent, cmdline, now);
        let view = View { name: proc.name.clone(), path: proc.path.clone(), parent_name: parent.to_string(), system, cmdline: Some(cmdline.to_string()), served, siege, ..View::default() };
        let outcome = score_process(&view, now, &self.policy, &self.shapes, &self.system_root);
        let reason = containment_reason(&outcome);
        if reason.is_empty() {
            if served && self.sieges.get(&proc.ppid).copied().unwrap_or(0.0) <= now {
                let shapes = self.habits.entry(parent.to_lowercase()).or_default();
                if shapes.len() < 300 {
                    shapes.insert(Self::shape(cmdline)); // an ordinary command of this service: remembered as normal
                }
            }
            return false;
        }
        let identity = (proc.pid, proc.started);
        let key = self.case_key(proc, parent);
        if self.hands.is_some() && self.held_back(&key, &reason, now) {
            return false;
        }
        self.sieges.insert(proc.ppid, now + SIEGE_SECONDS);
        if self.hands.is_none() || protected(proc, &self.own) || self.trusted.contains(&self.case_key(proc, parent)) || self.released.contains(&identity) || self.paused.contains(&identity) {
            return false;
        }
        if !frozen && !self.hands.as_mut().is_some_and(|hands| hands.suspend(proc.pid)) {
            return false; // frozen first: from here it starts nothing more
        }
        if self.mode == Mode::Kill {
            // Whatever it had already started goes too, the newest first.
            let running = self.sensor.running_now();
            let (mut members, mut queue): (Vec<u32>, Vec<u32>) = (Vec::new(), vec![proc.pid]);
            while let Some(above) = queue.pop() {
                if members.len() >= 64 {
                    break;
                }
                let found: Vec<u32> = running.iter().filter(|other| other.ppid == above && !self.own.contains(&other.pid) && other.pid != proc.pid).map(|other| other.pid).collect();
                members.extend(&found);
                queue.extend(&found);
            }
            let lived = self.sensor.lived_ms(proc);
            // Where each of them lived is read before they are ended: that is how their files are found afterwards.
            let mut ended: Vec<Proc> = running.iter().filter(|other| members.contains(&other.pid)).cloned().collect();
            ended.push(proc.clone());
            let spaces = self.spaces(&ended);
            ended.extend(Self::named_files(proc, cmdline));
            let hands = self.hands.as_mut().expect("checked above");
            let done = members.iter().rev().filter(|pid| hands.kill(**pid)).count() + usize::from(hands.kill(proc.pid));
            if done > 0 && self.more.after_event.len() < 64 {
                self.more.after_event.push((self.case_key(proc, parent), ended, spaces, now));
            }
            let why = format!("{}{}", clean(&reason, 118), lived.map(|ms| format!(" (ended {ms:.1} ms after it started)")).unwrap_or_default());
            self.instant.insert(identity, json!({"action": if done > 0 { "stopped" } else { "stop_failed" }, "programs": done.min(64), "reason": why}));
            self.paused.insert(identity);
        }
        self.urgent = true; // report it now
        true
    }

    /// What responders did at the event and have not yet said with a case: (process id, the action).
    pub fn acted_at_the_event(&self) -> Vec<(u32, Value)> {
        let mut found: Vec<(u32, Value)> = self.instant.iter().map(|(identity, action)| (identity.0, action.clone())).collect();
        found.sort_by_key(|(pid, _)| *pid);
        found
    }

    /// The programs that are held to their normal commands right now.
    pub fn under_attack(&self) -> Vec<u32> {
        let mut found: Vec<u32> = self.sieges.keys().copied().collect();
        found.sort_unstable();
        found
    }

    /// How many normal commands are known for each network-facing program.
    pub fn habit_counts(&self) -> Vec<(String, usize)> {
        let mut found: Vec<(String, usize)> = self.habits.iter().map(|(name, shapes)| (name.clone(), shapes.len())).collect();
        found.sort();
        found
    }

    pub(crate) fn digest(&self, subject: &str) -> String {
        let hash = Sha256::digest(format!("{}:sentinel:{subject}", self.salt).as_bytes());
        hash.iter().take(16).map(|byte| format!("{byte:02x}")).collect()
    }

    /// A shell or loader is one program doing many jobs: it is a different case under each program that starts it.
    pub fn case_key(&self, proc: &Proc, parent_name: &str) -> String {
        let lowered = proc.name.to_lowercase();
        let runs_others = is_script_host(&lowered) || LOADER_TOOLS.contains(&lowered.as_str()) || DIRECTORY_TOOLS.contains(&lowered.as_str())
            || (self.sensor.system() != "windows" && starts(&lowered, INTERPRETER_PREFIXES));
        let subject = if proc.path.is_empty() { proc.name.to_lowercase() } else { proc.path.to_lowercase() };
        self.digest(&if runs_others { format!("{subject}|{}", parent_name.to_lowercase()) } else { subject })
    }

    /// True when the parent accepts network connections and is not a program whose work is starting shells.
    fn served(&self, ppid: u32, parent_name: &str) -> bool {
        self.sensor.system() != "windows" && self.listeners.contains(&ppid) && !starts(&parent_name.to_lowercase(), LISTENER_EXEMPT)
    }

    /// True for a program this agent started itself.
    fn mine(&self, proc: &Proc) -> bool {
        self.myself != 0 && proc.ppid == self.myself
    }

    /// A new process worth following even before it opens a connection.
    pub(crate) fn interesting(&self, proc: &Proc, parent_name: &str) -> bool {
        if self.mine(proc) {
            return false;
        }
        let (lowered, above, system) = (proc.name.to_lowercase(), parent_name.to_lowercase(), self.sensor.system());
        if lowered == "cmstp.exe" {
            return is_script_host(&above);
        }
        if is_script_host(&lowered) || DIRECTORY_TOOLS.contains(&lowered.as_str()) {
            return true; // the command line is read at once; the scorer decides
        }
        if MAIL_PARENTS.contains(&above.as_str()) || ARCHIVE_PARENTS.contains(&above.as_str()) {
            return user_writable(&proc.path, system);
        }
        if system != "windows" && starts(&lowered, INTERPRETER_PREFIXES) && (starts(&above, WEB_SERVER_PREFIXES) || self.served(proc.ppid, &above)) {
            return true;
        }
        system != "windows" && unix_temp().is_match(&proc.path)
    }

    fn find(&self, identity: Identity) -> Option<usize> {
        self.tracked.iter().position(|tracked| (tracked.proc.pid, tracked.proc.started) == identity)
    }

    pub(crate) fn follow(&mut self, proc: &Proc, parent_name: &str, cmdline: Option<String>, now: f64) -> usize {
        let index = match self.find((proc.pid, proc.started)) {
            Some(index) => index,
            None => {
                let file_age = self.sensor.file_age(&proc.path, now);
                self.tracked.push(Tracked {
                    proc: proc.clone(), first_seen: now, cmdline: None, signature: None, file_age, parent_name: String::new(), last_alive: now,
                    noted: false, served: false, counted: false, remotes: Vec::new(), contacts: Vec::new(), inbound: Vec::new(), seen: HashSet::new(), origin: String::new(),
                });
                self.tracked.len() - 1
            }
        };
        let served = self.served(proc.ppid, parent_name);
        let tracked = &mut self.tracked[index];
        if tracked.parent_name.is_empty() {
            tracked.parent_name = parent_name.to_string();
        }
        tracked.served = tracked.served || served;
        if cmdline.is_some() && tracked.cmdline.is_none() {
            tracked.cmdline = cmdline;
        }
        tracked.last_alive = now;
        index
    }

    /// Between full looks: notice processes that just started. True when there is a new one worth scoring now.
    pub fn fast(&mut self, now: f64) -> bool {
        let before = self.tracked.len();
        let procs = self.sensor.processes();
        let fresh: Vec<&Proc> = procs.iter().filter(|proc| !self.known.contains(&(proc.pid, proc.started))).collect();
        let wanted: Vec<(Proc, String)> = fresh.iter().filter_map(|proc| {
            let parent = procs.iter().find(|other| other.pid == proc.ppid).map(|other| other.name.clone()).unwrap_or_default();
            self.interesting(proc, &parent).then(|| ((*proc).clone(), parent))
        }).collect();
        self.known = procs.iter().map(|proc| (proc.pid, proc.started)).collect();
        if !wanted.is_empty() {
            let lines = self.sensor.command_lines(&wanted.iter().map(|(proc, _)| proc.pid).collect::<Vec<_>>());
            for (proc, parent) in &wanted {
                self.follow(proc, parent, lines.get(&proc.pid).cloned(), now);
            }
        }
        self.tracked.len() > before
    }

    fn contain(&mut self, index: usize, key: &str, procs: &[Proc], outcome: &Outcome, now: f64) -> Option<Value> {
        let subject = self.tracked[index].proc.clone();
        let identity = (subject.pid, subject.started);
        let reason = containment_reason(outcome);
        if reason.is_empty() || self.paused.contains(&identity) || self.released.contains(&identity) || protected(&subject, &self.own) {
            return None;
        }
        // Only a process that is running right now under that same identity. One that has already exited is
        // never signalled: its process id may belong to something else by now.
        if !procs.iter().any(|proc| proc.pid == subject.pid && proc.started == subject.started) {
            return None;
        }
        if self.hands.is_some() && self.held_back(key, &reason, now) {
            return None;
        }
        let (mut members, mut queue): (Vec<Proc>, std::collections::VecDeque<Proc>) = (Vec::new(), std::collections::VecDeque::from([subject]));
        while let Some(proc) = queue.pop_front() {
            if members.len() >= 64 {
                break;
            }
            if protected(&proc, &self.own) {
                continue;
            }
            queue.extend(procs.iter().filter(|other| other.ppid == proc.pid).cloned());
            members.push(proc);
        }
        self.hands.as_ref()?;
        let reason = clean(&reason, 160);
        if self.mode == Mode::Kill {
            // Children first, so nothing is left to restart the rest. Never retried on the same process.
            let spaces = self.spaces(&members);
            let hands = self.hands.as_mut()?;
            let done = members.iter().rev().filter(|proc| hands.kill(proc.pid)).count();
            self.paused.extend(members.iter().map(|proc| (proc.pid, proc.started)));
            if done > 0 {
                let known_bad = self.known_bad(self.tracked[index].remotes.iter().map(|((address, _), _)| address.clone()));
                let since = self.tracked[index].first_seen;
                let named = Self::named_files(&self.tracked[index].proc, self.tracked[index].cmdline.as_deref().unwrap_or(""));
                members.extend(named);
                let steps = self.clean_after(key, &members, procs, &known_bad, since, &spaces, now);
                if !steps.is_empty() {
                    self.more.cleanups.insert(key.to_string(), steps);
                }
            }
            return Some(json!({"action": if done > 0 { "stopped" } else { "stop_failed" }, "programs": done, "reason": reason}));
        }
        let hands = self.hands.as_mut()?;
        let done: Vec<Identity> = members.iter().filter(|proc| hands.suspend(proc.pid)).map(|proc| (proc.pid, proc.started)).collect();
        if done.is_empty() {
            return Some(json!({"action": "pause_failed", "programs": 0, "reason": reason}));
        }
        self.paused.extend(done.iter().copied());
        let name = self.tracked[index].proc.name.clone();
        self.remember_paused(key, &done, &name, now);
        Some(json!({"action": "paused", "programs": done.len(), "reason": reason}))
    }

    fn enrich(&mut self, now: f64) {
        let wanted: Vec<u32> = self.tracked.iter().filter(|tracked| {
            let name = tracked.proc.name.to_lowercase();
            tracked.cmdline.is_none() && (is_script_host(&name) || DIRECTORY_TOOLS.contains(&name.as_str()) || starts(&name, INTERPRETER_PREFIXES))
        }).map(|tracked| tracked.proc.pid).collect();
        if !wanted.is_empty() {
            let lines = self.sensor.command_lines(&wanted);
            for tracked in self.tracked.iter_mut().filter(|tracked| tracked.cmdline.is_none() && wanted.contains(&tracked.proc.pid)) {
                tracked.cmdline = Some(lines.get(&tracked.proc.pid).cloned().unwrap_or_default());
            }
        }
        let mut unsigned: Vec<String> = Vec::new();
        let windows = self.sensor.system() == "windows";
        for tracked in self.tracked.iter_mut() {
            let path = &tracked.proc.path;
            if tracked.signature.is_none() && !path.is_empty() {
                if let Some(known) = self.signatures.get(path) {
                    tracked.signature = Some(known.clone());
                } else if windows && !path.to_lowercase().starts_with(&self.system_root) && !unsigned.contains(path) {
                    unsigned.push(path.clone());
                }
            }
        }
        if !unsigned.is_empty() {
            unsigned.truncate(8);
            let found = self.sensor.signatures(&unsigned);
            let later = self.sensor.signatures_later();
            for path in &unsigned {
                match found.get(path) {
                    Some(known) => {
                        self.signatures.insert(path.clone(), known.clone());
                    }
                    None if !later => {
                        self.signatures.insert(path.clone(), Default::default());
                    }
                    None => {}
                }
            }
            for tracked in self.tracked.iter_mut() {
                if tracked.signature.is_none() {
                    if let Some(known) = self.signatures.get(&tracked.proc.path) {
                        tracked.signature = Some(known.clone());
                    }
                }
            }
        }
        let unnamed = self.tracked.iter().any(|tracked| tracked.remotes.iter().any(|((address, _), names)| names.is_empty() && is_internet(address)));
        if unnamed && now - self.names_at >= 60.0 {
            self.names_at = now;
            let found = self.sensor.names();
            if !found.is_empty() {
                self.names = found;
            }
        }
        if !self.names.is_empty() {
            for tracked in self.tracked.iter_mut() {
                for ((address, _), names) in tracked.remotes.iter_mut() {
                    if let Some(known) = self.names.get(address) {
                        names.extend(known.iter().cloned());
                    }
                }
            }
        }
        if !self.more.watch.is_empty() {
            for tracked in self.tracked.iter_mut() {
                for ((address, _), names) in tracked.remotes.iter_mut() {
                    if let Some(host) = self.more.watch.get(address) {
                        names.insert(format!("~{host}"));
                    }
                }
            }
        }
    }

    fn chain(proc: &Proc, procs: &[Proc]) -> Vec<Value> {
        let (mut chain, mut seen, mut ppid) = (Vec::new(), HashSet::from([proc.pid]), proc.ppid);
        for _ in 0..6 {
            let Some(above) = procs.iter().find(|other| other.pid == ppid) else { break };
            if seen.contains(&above.pid) || above.pid == 0 {
                break;
            }
            seen.insert(above.pid);
            chain.push(json!({"name": clean(&above.name, 80), "path": clean(&above.path, 300)}));
            ppid = above.ppid;
        }
        chain
    }

    fn signal_values(outcome: &Outcome, keep: impl Fn(&str) -> bool) -> Vec<Value> {
        outcome.signals.iter().filter(|signal| keep(&signal.category)).map(|signal| json!({"id": signal.id, "points": signal.points, "category": signal.category, "evidence": signal.evidence})).collect()
    }

    /// One antivirus detection from the last week becomes one case, reported once.
    fn detection_cases(&mut self, now: f64) -> Vec<Value> {
        let mut cases = Vec::new();
        for item in self.sensor.detections() {
            if self.detections_seen.contains(&item.id) || now - item.at > 7.0 * 86400.0 || cases.len() >= 4 {
                continue;
            }
            let view = View {
                name: "Windows Defender detection".into(), parent_name: item.process.clone(), system: self.sensor.system().into(),
                detections: vec![Detection { name: Some(item.name.clone()), executed: item.executed, active: item.active }], ..View::default()
            };
            let outcome = score_process(&view, now, &HashMap::new(), &[], &self.system_root);
            cases.push(json!({"key": self.digest(&format!("detection:{}", item.id)), "level": outcome.level, "score": outcome.score, "name": "Windows Defender detection",
                "path": clean(&item.resource, 300), "parent": clean(&item.process, 80), "categories": outcome.categories,
                "signals": Self::signal_values(&outcome, |category| category == "antivirus" || category == "behaviour"),
                "remotes": [], "first_seen": item.at.trunc() as i64, "observed_at": now.trunc() as i64, "detection": item.id}));
        }
        cases
    }

    /// One case per account and kind of directory attack seen in the Windows Security log.
    fn directory_cases(&mut self, found: Vec<Activity>, now: f64) -> Vec<Value> {
        let mut cases = Vec::new();
        for event in found.into_iter().take(8) {
            let key = self.digest(&format!("directory:{}:{}", event.kind, event.account.to_lowercase()));
            if self.trusted.contains(&key) || self.reported.get(&key).is_some_and(|previous| now - previous.1 < 3600.0) {
                continue;
            }
            let view = View { name: "Windows directory activity".into(), system: self.sensor.system().into(), events: vec![(event.kind.clone(), event.count)], ..View::default() };
            let outcome = score_process(&view, now, &HashMap::new(), &[], &self.system_root);
            if outcome.level == "SUSPECT" || outcome.level == "HOSTILE" {
                cases.push(json!({"key": key, "level": outcome.level, "score": outcome.score, "name": format!("Directory account {}", event.account), "path": "",
                    "parent": "", "categories": outcome.categories, "signals": Self::signal_values(&outcome, |_| true), "remotes": [],
                    "first_seen": now.trunc() as i64, "observed_at": now.trunc() as i64}));
            }
        }
        cases
    }

    /// One full look at the machine. Returns the cases to report now, the most serious first.
    pub fn tick(&mut self, now: f64) -> Vec<Value> {
        self.tick_with(now, &[])
    }

    /// A full look, with the programs the feeds reported since the last one: those worth following are scored
    /// even if they have already ended.
    pub fn tick_with(&mut self, now: f64, started: &[Snap]) -> Vec<Value> {
        let (procs, conns) = (self.sensor.processes(), self.sensor.connections());
        self.listeners = self.sensor.listening();
        self.urgent = false;
        self.clean_after_events(&procs, now);
        self.sieges.retain(|_, until| *until > now);
        self.ticks += 1;
        self.more.seen = (procs.len(), conns.len());
        if !self.more.adopting.is_empty() {
            self.adopt(&procs, now);
        }
        self.notice_let_go();
        for snap in started {
            if self.interesting(&snap.proc, &snap.parent) {
                self.follow(&snap.proc, &snap.parent, Some(snap.cmdline.clone()), now);
            }
        }
        let by_pid = |pid: u32| procs.iter().find(|proc| proc.pid == pid);
        let mut live: HashSet<Identity> = HashSet::new();
        for tracked in self.tracked.iter_mut() {
            let identity = (tracked.proc.pid, tracked.proc.started);
            if by_pid(identity.0).is_some_and(|proc| proc.started == identity.1) {
                tracked.last_alive = now;
            }
            if now - tracked.last_alive <= 30.0 && tracked.cmdline.is_some() {
                live.insert(identity); // followed from its start: scored even if it has already exited
            }
        }
        for conn in &conns {
            let Some(proc) = by_pid(conn.pid) else { continue };
            if conn.raddr.is_empty() || conn.raddr == "0.0.0.0" || conn.raddr == "::" || self.mine(proc) {
                continue;
            }
            let identity = (proc.pid, proc.started);
            live.insert(identity);
            let index = match self.find(identity) {
                Some(index) => index,
                None => {
                    let file_age = self.sensor.file_age(&proc.path, now);
                    self.tracked.push(Tracked {
                        proc: proc.clone(), first_seen: now, cmdline: None, signature: None, file_age, parent_name: String::new(), last_alive: now,
                        noted: false, served: false, counted: false, remotes: Vec::new(), contacts: Vec::new(), inbound: Vec::new(), seen: HashSet::new(), origin: String::new(),
                    });
                    self.tracked.len() - 1
                }
            };
            // This machine's own addresses, public ones included: how its neighbours recognise it.
            if !conn.laddr.is_empty() && (crate::net::neighbour(&conn.laddr) || is_internet(&conn.laddr)) {
                self.more.addresses.insert(conn.laddr.clone(), now);
            }
            if crate::net::neighbour(&conn.raddr) {
                self.more.peers.insert((conn.raddr.clone(), if conn.inbound { conn.lport } else { conn.rport }, if conn.inbound { "in" } else { "out" }), now);
            }
            let tracked = &mut self.tracked[index];
            if conn.inbound {
                let sources = match tracked.inbound.iter().position(|(port, _)| *port == conn.lport) {
                    Some(at) => &mut tracked.inbound[at].1,
                    None => {
                        tracked.inbound.push((conn.lport, Vec::new()));
                        &mut tracked.inbound.last_mut().expect("just pushed").1
                    }
                };
                match sources.iter_mut().find(|(address, _)| *address == conn.raddr) {
                    Some(entry) => entry.1 = now,
                    None => sources.push((conn.raddr.clone(), now)),
                }
                continue;
            }
            let key = (conn.raddr.clone(), conn.rport);
            if !tracked.remotes.iter().any(|(known, _)| *known == key) {
                tracked.remotes.push((key.clone(), BTreeSet::new()));
            }
            if tracked.seen.insert((conn.lport, conn.raddr.clone(), conn.rport)) {
                let stamps = match tracked.contacts.iter().position(|(known, _)| *known == key) {
                    Some(at) => &mut tracked.contacts[at].1,
                    None => {
                        tracked.contacts.push((key, Vec::new()));
                        &mut tracked.contacts.last_mut().expect("just pushed").1
                    }
                };
                stamps.push(now);
                if stamps.len() > 64 {
                    let extra = stamps.len() - 64;
                    stamps.drain(..extra);
                }
            }
        }
        // A shell with no connection of its own still matters when a web server or a document started it.
        let windows = self.sensor.system() == "windows";
        for proc in &procs {
            let lowered = proc.name.to_lowercase();
            let Some(parent) = by_pid(proc.ppid) else { continue };
            let above = parent.name.to_lowercase();
            if above.is_empty() || self.mine(proc) {
                continue;
            }
            let watch = if lowered == "cmstp.exe" {
                is_script_host(&above)
            } else if is_script_host(&lowered) || DIRECTORY_TOOLS.contains(&lowered.as_str()) {
                DIRECTORY_TOOLS.contains(&lowered.as_str()) || is_document_parent(&above) || REMOTE_SESSION_PARENTS.iter().any(|(name, _)| *name == above)
                    || starts(&above, WEB_SERVER_PREFIXES) || self.served(proc.ppid, &above) || (above == "explorer.exe" && lowered != "cmd.exe" && lowered != "rundll32.exe")
            } else if !windows && starts(&lowered, INTERPRETER_PREFIXES) && (starts(&above, WEB_SERVER_PREFIXES) || self.served(proc.ppid, &above)) && !starts(&lowered, WEB_SERVER_PREFIXES) {
                true
            } else {
                (MAIL_PARENTS.contains(&above.as_str()) || ARCHIVE_PARENTS.contains(&above.as_str())) && user_writable(&proc.path, self.sensor.system())
            };
            if watch {
                live.insert((proc.pid, proc.started));
                self.follow(proc, &parent.name, None, now);
            }
        }
        self.tracked.retain(|tracked| {
            let identity = (tracked.proc.pid, tracked.proc.started);
            live.contains(&identity) || by_pid(identity.0).is_some() || now - tracked.last_alive <= 30.0
        });
        self.enrich(now);
        if !self.more.contained.is_empty() {
            self.fallback(&procs, now);
        }

        let mut cases: Vec<Value> = Vec::new();
        for index in 0..self.tracked.len() {
            let proc = self.tracked[index].proc.clone();
            if !live.contains(&(proc.pid, proc.started)) {
                continue;
            }
            // The parent: the running one, or a stand-in with the name read when the program started.
            let mut parent: Option<Proc> = by_pid(proc.ppid).cloned();
            if let Some(found) = &parent {
                self.tracked[index].parent_name = found.name.clone();
            } else if !self.tracked[index].parent_name.is_empty() {
                parent = Some(Proc { pid: proc.ppid, ppid: 0, name: self.tracked[index].parent_name.clone(), ..Proc::default() });
            }
            // Look through "cmd /c powershell ..." to whoever really started it.
            let (mut above, mut moved) = (parent.clone(), false);
            for _ in 0..4 {
                let Some(current) = &above else { break };
                if !PLAIN_SHELLS.contains(&current.name.to_lowercase().as_str()) {
                    break;
                }
                above = by_pid(current.ppid).cloned();
                moved = true;
            }
            if let (Some(found), true, true) = (&above, parent.is_some(), moved) {
                self.tracked[index].origin = found.name.clone();
            }
            let stream_key = above.as_ref().map(|found| found.pid).unwrap_or(proc.ppid);
            if !self.tracked[index].noted && self.tracked[index].cmdline.as_deref().is_some_and(|line| !line.is_empty()) {
                self.tracked[index].noted = true;
                let line: String = self.tracked[index].cmdline.as_deref().unwrap_or("").split_whitespace().collect::<Vec<_>>().join(" ").chars().take(400).collect();
                let first_seen = self.tracked[index].first_seen;
                let stream = match self.streams.iter().position(|(key, _)| *key == stream_key) {
                    Some(at) => &mut self.streams[at].1,
                    None => {
                        self.streams.push((stream_key, Vec::new()));
                        &mut self.streams.last_mut().expect("just pushed").1
                    }
                };
                stream.push((first_seen, line));
                if stream.len() > 64 {
                    let extra = stream.len() - 64;
                    stream.drain(..extra);
                }
            }
            let marks = self.streams.iter().find(|(key, _)| *key == stream_key).map(|(_, stream)| agent_marks(stream, now, 180.0)).unwrap_or_default();
            let parent_name = parent.as_ref().map(|found| found.name.clone()).unwrap_or_default();
            let key = self.case_key(&proc, &parent_name);
            let siege = self.tracked[index].served && self.unusual(proc.ppid, &parent_name, self.tracked[index].cmdline.as_deref().unwrap_or(""), now);
            let tracked = &self.tracked[index];
            let labels: Vec<String> = tracked.remotes.iter().filter(|((address, _), _)| is_internet(address))
                .map(|((address, _), names)| names.iter().next().cloned().unwrap_or_else(|| address.clone())).collect::<BTreeSet<_>>().into_iter().collect();
            let (days, overlap) = match self.ledger.get(&key) {
                Some(entry) => ((now - entry.first) / 86400.0, if labels.is_empty() { 0.0 } else { labels.iter().filter(|label| entry.remotes.contains(label)).count() as f64 / labels.len() as f64 }),
                None => (0.0, 0.0),
            };
            let view = View {
                name: proc.name.clone(), path: proc.path.clone(), parent_name: parent_name.clone(), system: self.sensor.system().to_string(),
                cmdline: tracked.cmdline.clone(), signature: tracked.signature.clone(),
                remotes: tracked.remotes.iter().map(|((address, port), names)| Remote { address: address.clone(), port: *port as u16, names: names.iter().cloned().collect() }).collect(),
                contacts: tracked.contacts.iter().map(|((address, port), stamps)| (address.clone(), *port as u16, stamps.clone())).collect(),
                inbound: tracked.inbound.iter().map(|(port, sources)| (*port as u16, sources.clone())).collect(),
                trusted: self.trusted.contains(&key), baseline_days: days, baseline_overlap: overlap, detections: Vec::new(), file_age: tracked.file_age, events: Vec::new(),
                origin: tracked.origin.clone(), agent: marks, exits: self.exits.clone(), fleet: self.fleet.clone(), suspects: self.suspects.clone(),
                served: tracked.served, siege, jumped: false, handed: false, new_keyboard: false,
            };
            let outcome = score_process(&view, now, &self.policy, &self.shapes, &self.system_root);
            if !labels.is_empty() {
                let entry = self.ledger.entry(key.clone()).or_insert(LedgerEntry { first: now, last: now, remotes: Vec::new() });
                entry.last = now;
                let all: BTreeSet<String> = entry.remotes.iter().cloned().chain(labels.iter().cloned()).collect();
                entry.remotes = all.into_iter().take(40).collect();
            }
            if (outcome.level == "SUSPECT" || outcome.level == "HOSTILE") && !self.trusted.contains(&key) {
                let action = if self.hands.is_some() { self.contain(index, &key, &procs, &outcome, now) } else { None };
                let action = action.or_else(|| self.instant.remove(&(proc.pid, proc.started))); // a responder already ended it, at the event
                let through = outcome.signals.iter().any(|signal| signal.id == "shell_from_web_server") && !containment_reason(&outcome).is_empty();
                if through {
                    self.sieges.insert(proc.ppid, now + SIEGE_SECONDS); // the service it came through is under attack
                }
                let previous = self.reported.get(&key).cloned();
                let rank = |level: &str| LEVELS.iter().position(|known| *known == level).unwrap_or(0);
                let worse = previous.as_ref().is_some_and(|before| rank(&outcome.level) > rank(&before.0) || outcome.score >= before.2 + 2);
                if !self.tracked[index].counted {
                    self.tracked[index].counted = true;
                    if previous.is_some() {
                        *self.repeats.entry(key.clone()).or_insert(0) += 1; // the same program under the same parent, started again
                    }
                }
                let repeated = self.repeats.get(&key).copied().unwrap_or(0);
                let again = previous.as_ref().is_some_and(|before| repeated > 0 && now - before.1 >= 60.0);
                if action.is_some() || previous.is_none() || worse || again || previous.as_ref().is_some_and(|before| now - before.1 >= 6.0 * 3600.0) {
                    let tracked = &self.tracked[index];
                    let mut remotes: Vec<Value> = tracked.remotes.iter().filter(|((address, _), _)| is_internet(address)).take(6)
                        .map(|((address, port), names)| json!({"address": clean(address, 60), "port": port, "names": names.iter().take(2).map(|name| clean(name, 120)).collect::<Vec<_>>(), "direction": "out"})).collect();
                    remotes.extend(tracked.inbound.iter().flat_map(|(port, sources)| sources.iter().take(2).filter(|(address, _)| is_internet(address))
                        .map(move |(address, _)| json!({"address": clean(address, 60), "port": port, "names": [], "direction": "in"}))).take(2));
                    let name = clean(&proc.name, 80);
                    let mut case = json!({"key": key, "level": outcome.level, "score": outcome.score, "name": if name.is_empty() { "unknown program".to_string() } else { name },
                        "path": clean(&proc.path, 300), "parent": clean(&parent_name, 80), "categories": outcome.categories,
                        "signals": Self::signal_values(&outcome, |_| true).into_iter().take(12).collect::<Vec<_>>(), "remotes": remotes,
                        "first_seen": tracked.first_seen.trunc() as i64, "observed_at": now.trunc() as i64, "chain": Self::chain(&proc, &procs)});
                    if repeated > 0 {
                        case["repeats"] = json!(repeated.min(9999));
                        self.repeats.remove(&key);
                    }
                    if let Some(action) = action {
                        case["actions"] = json!([action]);
                    } else if let Some(why) = self.more.left.remove(&key) {
                        case["held"] = json!(why);
                    }
                    if let Some(steps) = self.more.cleanups.remove(&key) {
                        case["cleanup"] = json!(steps);
                    }
                    if through {
                        self.more.attacks.insert(proc.ppid, (case.clone(), now, parent_name.to_lowercase()));
                    }
                    cases.push(case);
                }
            }
        }
        if now - self.detections_at >= 300.0 {
            self.detections_at = now;
            cases.extend(self.detection_cases(now));
        }
        if now - self.directory_at >= 60.0 {
            if let Some(found) = self.sensor.directory_events() {
                self.directory_at = now;
                cases.extend(self.directory_cases(found, now));
            }
        }
        cases.extend(self.signin_cases(now));
        cases.extend(self.startup_cases(&procs, now));
        cases.append(&mut self.more.extra); // startup entries judged the instant they appeared
        if self.more.web.is_some() && now - self.more.web_at >= 5.0 {
            self.more.web_at = now;
            let found = self.web_cases(now);
            self.remember_web_attacks(&found, now);
            cases.extend(found);
        }
        self.callback_cases(now, &mut cases);
        self.streams.retain(|(_, stream)| stream.last().is_some_and(|(stamp, _)| now - stamp <= 900.0));
        self.keep(now);
        cases.sort_by(|a, b| b["score"].as_i64().cmp(&a["score"].as_i64()));
        cases.truncate(MAX_CASES_PER_REPORT);
        cases
    }

    /// The service (or the no-service log) has these cases now: do not say them again until something changes.
    pub fn mark_reported(&mut self, cases: &[Value], now: f64) {
        for case in cases {
            if let (Some(key), Some(level), Some(score)) = (case["key"].as_str(), case["level"].as_str(), case["score"].as_i64()) {
                self.reported.insert(key.to_string(), (level.to_string(), now, score));
            }
            if let Some(id) = case["detection"].as_str() {
                self.detections_seen.insert(id.to_string());
                self.more.ledger_saved = 0.0; // remember it at the next look, so a restart does not report it again
            }
        }
    }

    /// The processes this watcher has frozen or ended, by identity.
    pub fn acted_on(&self) -> usize {
        self.paused.len()
    }
}
