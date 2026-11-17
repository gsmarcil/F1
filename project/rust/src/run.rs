//! Running the agent: the feeds, the responders, the full looks, and either the reports to a service or the
//! cases kept on the machine. What differs between systems
//! is behind `machine`.

#![cfg(any(target_os = "linux", target_os = "macos", windows))]

use crate::agent::{self, call, jitter, local_line, now, CallError, State};
use crate::linux::Snap;
use crate::machine::{self, Feeds, Live, RealHands};
use crate::tool::{Looked, Shared};
use crate::watch::{Mode, Watcher, MAX_CASES_PER_REPORT};
use serde_json::Value;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const TICK_SECONDS: u64 = 5;
const RESPONDERS: usize = 4;
static STOP: AtomicBool = AtomicBool::new(false);
/// Set when the agent replaced its own program file: it stops as it always does, then starts the new one.
static AGAIN: AtomicBool = AtomicBool::new(false);

/// How long a fresh install settles in, in hours, as text bits of a float. 24 unless `run --learn` says otherwise.
static LEARN_HOURS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0x4038_0000_0000_0000);

pub fn set_learn_hours(hours: f64) {
    LEARN_HOURS.store(hours.max(0.0).to_bits(), Ordering::SeqCst);
}

/// Whether the privacy shield runs unless the owner said otherwise on this machine. On, unless `run --shield off`.
static SHIELD: AtomicBool = AtomicBool::new(true);

pub fn set_shield(on: bool) {
    SHIELD.store(on, Ordering::SeqCst);
}

/// The privacy shield's memory, and a thread that looks the tracker names up again every half hour.
fn start_shield(state: &State) -> Arc<Mutex<crate::shield::Shield>> {
    let shield = Arc::new(Mutex::new(crate::shield::Shield::load(&state.directory, f64::from_bits(LEARN_HOURS.load(Ordering::SeqCst)), now())));
    let (kept, directory) = (shield.clone(), state.directory.clone());
    let _ = std::thread::Builder::new().name("garrett-shield".into()).spawn(move || {
        std::thread::sleep(Duration::from_secs(10));
        loop {
            // The names are only looked up while the shield is on: a machine with it off asks DNS nothing.
            if crate::shield::enabled(&directory, SHIELD.load(Ordering::SeqCst)) {
                let found = crate::shield::look_up();
                match kept.lock() {
                    Ok(mut shield) => shield.learn_addresses(&found, now()),
                    Err(_) => return,
                }
            }
            std::thread::sleep(Duration::from_secs_f64(1800.0 * jitter(0.8, 1.2)));
        }
    });
    shield
}

/// What the owner said on this machine since the last look: cases confirmed as attacks, and (with no service)
/// what was learned from all their verdicts.
fn take_local(running: &Running, state: &State, alone: bool) {
    let confirmed = std::fs::read(state.directory.join("confirmed.json")).ok().and_then(|raw| serde_json::from_slice::<Value>(&raw).ok()).unwrap_or_else(|| Value::Array(Vec::new()));
    let learned = if alone { crate::learn::learned(&state.directory) } else { Value::Null };
    if let Ok(mut watcher) = running.watcher.lock() {
        watcher.set_confirmed(&confirmed);
        if alone {
            watcher.set_policy(&learned["policy"]);
            watcher.set_shapes(&learned["shapes"]);
        }
    }
}

/// True when the agent stopped only to start its new version.
pub fn starting_again() -> bool {
    AGAIN.load(Ordering::SeqCst)
}

/// Look for a newer version a few minutes after starting and then four times a day, on a thread of its own, and
/// install it. The times are spread out, so a fleet never asks or restarts all at once.
pub fn keep_current() {
    let wait = |seconds: f64| std::thread::sleep(Duration::from_secs_f64(seconds * jitter(0.6, 1.4)));
    let first: f64 = std::env::var("GARRETT_UPDATE_AFTER").ok().and_then(|value| value.parse().ok()).unwrap_or(600.0);
    let _ = std::thread::Builder::new().name("garrett-update".into()).spawn(move || {
        wait(first);
        let mut said = String::new();
        loop {
            match crate::update::bring_current(&crate::update::source()) {
                Ok(crate::update::Outcome::Current) => said.clear(),
                Ok(crate::update::Outcome::Replaced(version)) => {
                    println!("garrett: updated itself from {} to {version}; starting the new version", crate::VERSION);
                    AGAIN.store(true, Ordering::SeqCst);
                    STOP.store(true, Ordering::SeqCst);
                    return;
                }
                Ok(crate::update::Outcome::Packaged(version)) => println!("garrett: version {version} is out; apt is installing it"),
                // Said once for each run of the same failure, so the machine's own log shows why it is behind.
                Err(why) if why != said => {
                    eprintln!("garrett: could not update itself: {why}");
                    said = why;
                }
                Err(_) => {}
            }
            wait(6.0 * 3600.0);
        }
    });
}

#[cfg(unix)]
extern "C" fn asked_to_stop(_signal: libc::c_int) {
    STOP.store(true, Ordering::SeqCst);
}

#[cfg(unix)]
fn listen_for_stop() {
    unsafe {
        libc::signal(libc::SIGTERM, asked_to_stop as *const () as libc::sighandler_t);
        libc::signal(libc::SIGINT, asked_to_stop as *const () as libc::sighandler_t);
    }
}

#[cfg(windows)]
fn listen_for_stop() {
    extern "system" fn asked_to_stop(_kind: u32) -> i32 {
        STOP.store(true, Ordering::SeqCst);
        1
    }
    extern "system" {
        fn SetConsoleCtrlHandler(handler: Option<extern "system" fn(u32) -> i32>, add: i32) -> i32;
    }
    unsafe { SetConsoleCtrlHandler(Some(asked_to_stop), 1) };
}

type Shared2 = Arc<Mutex<Watcher<Live, RealHands>>>;

struct Running {
    watcher: Shared2,
    looked: Shared,
    started: Arc<Mutex<Vec<Snap>>>,
    wake: Receiver<()>,
    feeds: Feeds,
    /// When connections were last asked for, and whether this look follows a responder's stop.
    refreshed: Option<Instant>,
    woken: bool,
    /// What would start each reported program again, asked once for each program file.
    persistence: std::collections::HashMap<String, Vec<Value>>,
    shield: Arc<Mutex<crate::shield::Shield>>,
    shield_said: usize,
    directory: std::path::PathBuf,
}

fn build(state: &State, salt: &str, mode: &str, clean: bool, fallback_kill: bool, decide_after: f64, never_block: &[String]) -> Running {
    let looked: Shared = Arc::new(Mutex::new(Looked::default()));
    machine::refresh_now(&looked);
    machine::background(&looked);
    let hands = (mode != "report").then(RealHands::default);
    let kind = match mode {
        "kill" => Mode::Kill,
        "decide" => Mode::Decide,
        _ => Mode::Pause,
    };
    let mut watcher = Watcher::new(machine::sensor(looked.clone()), hands, salt, kind, &machine::system_root());
    // This agent and every ancestor of it: never paused or stopped.
    let procs = looked.lock().map(|looked| looked.procs.clone()).unwrap_or_default();
    let mut pid = std::process::id();
    watcher.own.insert(pid);
    watcher.myself = pid;
    for _ in 0..16 {
        let Some(parent) = procs.iter().find(|proc| proc.pid == pid).map(|proc| proc.ppid).filter(|ppid| *ppid > 0 && !watcher.own.contains(ppid)) else { break };
        watcher.own.insert(parent);
        pid = parent;
    }
    // An install that has been watching before this does not settle in again.
    let fresh = !["sentinel-baseline.json", "sentinel-habits.json", "cases.jsonl"].iter().any(|name| state.directory.join(name).exists());
    watcher.keep_in(&state.directory, clean);
    watcher.settle_in(f64::from_bits(LEARN_HOURS.load(Ordering::SeqCst)), fresh, now());
    watcher.decide_with(fallback_kill, decide_after);
    watcher.never_block(never_block);
    watcher.set_web(crate::web::WebWatch::discover(now()));

    let (starts, received) = channel::<Snap>();
    let (wake_sender, wake) = channel::<()>();
    let feeds = Feeds::start(starts);
    watcher.event_feed = feeds.open();
    watcher.set_process_feed(feeds.process_feed());
    let folders = watcher.startup_folders();
    let watcher: Shared2 = Arc::new(Mutex::new(watcher));
    // At the network card. The table of neighbours is read every two seconds: a machine that starts answering
    // for the gateway is seen while it is doing it. On Linux the first packet of each arriving connection attempt
    // is read as well, by a thread that waits on the card itself.
    {
        let (watcher, directory) = (watcher.clone(), state.directory.clone());
        let _ = std::thread::Builder::new().name("garrett-gateway".into()).spawn(move || {
            let (mut watch, mut newer) = (crate::lan::GatewayWatch::default(), crate::lan::GatewayWatch::default());
            let mut keyboards = crate::devices::KeyboardWatch::new(&directory);
            let pause = if cfg!(target_os = "macos") { 30 } else { 2 }; // there it is asked through two programs
            let mut readings = 0u64;
            while !STOP.load(Ordering::SeqCst) {
                let mut found: Vec<crate::lan::Found> = crate::lan::read().and_then(|seen| watch.take(&seen, now())).into_iter().collect();
                // The newer kind of address is asked of the system's own tools: every half minute.
                if readings % (30 / pause) == 0 {
                    found.extend(crate::lan::read6().and_then(|seen| newer.take(&seen, now())));
                }
                readings += 1;
                for found in found {
                    match watcher.lock() {
                        Ok(mut watcher) => watcher.network_found(&found, now()),
                        Err(_) => return,
                    }
                }
                // Keyboards: one this machine never had is told to the watcher the moment it is seen.
                if crate::devices::keyboards().is_some_and(|present| keyboards.take(&present) > 0) {
                    match watcher.lock() {
                        Ok(mut watcher) => watcher.keyboard_arrived(now()),
                        Err(_) => return,
                    }
                }
                for _ in 0..pause {
                    if STOP.load(Ordering::SeqCst) {
                        return;
                    }
                    std::thread::sleep(Duration::from_secs(1));
                }
            }
        });
    }
    // macOS: the same first packets, through the system's packet device, on the card this machine sends out through.
    #[cfg(target_os = "macos")]
    {
        let watcher = watcher.clone();
        let _ = std::thread::Builder::new().name("garrett-card".into()).spawn(move || {
            std::thread::sleep(Duration::from_secs(20));
            let Some(card) = crate::lan::way_out_card() else { return };
            let mut watch = crate::lan::ScanWatch::default();
            let _ = crate::card::listen(&STOP, &card, |packet| {
                if let Some(found) = crate::lan::opening(packet).and_then(|(source, port)| watch.attempt(&source, port, now())) {
                    if let Ok(mut watcher) = watcher.lock() {
                        watcher.network_found(&found, now());
                    }
                }
            });
        });
    }
    #[cfg(target_os = "linux")]
    for newer in [false, true] {
        let watcher = watcher.clone();
        let _ = std::thread::Builder::new().name("garrett-card".into()).spawn(move || {
            let mut watch = crate::lan::ScanWatch::default();
            let _ = crate::lan::listen(&STOP, newer, |source, port| {
                if let Some(found) = watch.attempt(&source, port, now()) {
                    if let Ok(mut watcher) = watcher.lock() {
                        watcher.network_found(&found, now());
                    }
                }
            });
        });
    }
    // Below the system: read every few minutes by a thread of its own, so nothing slow is done while the watcher
    // is held. The first reading is the starting point; only a later change is handed over.
    {
        let (watcher, directory) = (watcher.clone(), state.directory.clone());
        let _ = std::thread::Builder::new().name("garrett-hardware".into()).spawn(move || {
            let mut watch = crate::hardware::HardwareWatch::new(&directory);
            std::thread::sleep(Duration::from_secs(5));
            let mut readings = 0u64;
            while !STOP.load(Ordering::SeqCst) {
                // The disks and the boot loader's files once an hour; everything else each time.
                let found = watch.take(crate::hardware::read(readings % 12 == 0), now());
                readings += 1;
                if !found.is_empty() {
                    match watcher.lock() {
                        Ok(mut watcher) => watcher.hardware_changed(&found, now()),
                        Err(_) => return,
                    }
                }
                for _ in 0..300 {
                    if STOP.load(Ordering::SeqCst) {
                        return;
                    }
                    std::thread::sleep(Duration::from_secs(1));
                }
            }
        });
    }
    let started: Arc<Mutex<Vec<Snap>>> = Arc::new(Mutex::new(Vec::new()));

    // The responders: each program start is judged at once by whichever of them is free, several at a time.
    let received = Arc::new(Mutex::new(received));
    for number in 0..RESPONDERS {
        let (received, watcher, started, wake_sender) = (received.clone(), watcher.clone(), started.clone(), wake_sender.clone());
        let _ = std::thread::Builder::new().name(format!("garrett-responder-{number}")).spawn(move || loop {
            let Ok(snap) = received.lock().map_err(|_| ()).and_then(|inbox| inbox.recv().map_err(|_| ())) else { return };
            let urgent = watcher.lock().map(|mut watcher| {
                watcher.on_exec(&snap, now());
                watcher.urgent
            }).unwrap_or(false);
            if let Ok(mut list) = started.lock() {
                list.push(snap);
                let extra = list.len().saturating_sub(2000);
                list.drain(..extra);
            }
            if urgent {
                let _ = wake_sender.send(());
            }
        });
    }
    // A startup place changed this instant: judge it now.
    let (changed_sender, changed) = channel::<()>();
    if machine::startup_signal(&folders, changed_sender).is_ok() {
        let (watcher, wake_sender) = (watcher.clone(), wake_sender.clone());
        let _ = std::thread::Builder::new().name("garrett-startup-judge".into()).spawn(move || {
            while changed.recv().is_ok() {
                std::thread::sleep(Duration::from_millis(2)); // let a writer finish its line
                while changed.try_recv().is_ok() {}
                if watcher.lock().map(|mut watcher| watcher.startup_changed(now())).unwrap_or(false) {
                    let _ = wake_sender.send(());
                }
            }
        });
    }
    Running { watcher, looked, started, wake, feeds, refreshed: None, woken: false, persistence: std::collections::HashMap::new(), shield: start_shield(state), shield_said: usize::MAX, directory: state.directory.clone() }
}

impl Running {
    /// The privacy shield's part of a look: note which programs talk to trackers, and refuse what may be refused.
    fn shield_look(&mut self) {
        let on = crate::shield::enabled(&self.directory, SHIELD.load(Ordering::SeqCst));
        let wanted = if on {
            let (procs, conns) = self.looked.lock().map(|looked| (looked.procs.clone(), looked.conns.clone())).unwrap_or_default();
            match self.shield.lock() {
                Ok(mut shield) => {
                    shield.note(&procs, &conns, now());
                    shield.cut(now())
                }
                Err(_) => Vec::new(),
            }
        } else {
            Vec::new()
        };
        // The firewall is written here, with the watcher let go: writing it takes many commands on some systems,
        // and a responder must never wait behind them.
        let change = self.watcher.lock().ok().and_then(|mut watcher| {
            watcher.set_shield(&wanted);
            watcher.block_wanted()
        });
        if let Some(target) = change {
            use crate::watch::Hands;
            let done = RealHands::default().block(&target);
            if let Ok(mut watcher) = self.watcher.lock() {
                watcher.block_done(target, done);
            }
        }
        if wanted.len() != self.shield_said {
            // What is refused changed: the record the commands read is written now, not at the next minute.
            if let Ok(mut shield) = self.shield.lock() {
                shield.save(now());
            }
            if !wanted.is_empty() {
                println!("garrett: privacy shield: {} tracker address(es) refused at the firewall (see: garrett shield)", wanted.len());
            } else if self.shield_said != usize::MAX && self.shield_said > 0 {
                println!("garrett: privacy shield: nothing is refused now");
            }
            self.shield_said = wanted.len();
        }
    }

    /// Move what the feeds reported to the responders.
    fn pump(&mut self) {
        if self.feeds.pump() {
            let open = self.feeds.open();
            if let Ok(mut watcher) = self.watcher.lock() {
                watcher.event_feed = open;
            }
        }
    }

    /// One full look. The slow questions are asked first, without holding the watcher.
    fn look(&mut self) -> Vec<Value> {
        // A look that follows a stop is there to say so and to clean up: it needs what is running now, and the
        // connections asked for a moment ago still serve. Connections are asked for again at the usual pace.
        if self.woken && self.refreshed.is_some_and(|at| at.elapsed() < Duration::from_secs(TICK_SECONDS)) {
            machine::refresh_processes(&self.looked);
        } else {
            machine::refresh_now(&self.looked);
            self.refreshed = Some(Instant::now());
        }
        self.woken = false;
        let started: Vec<Snap> = self.started.lock().map(|mut list| std::mem::take(&mut *list)).unwrap_or_default();
        let mut cases = self.watcher.lock().map(|mut watcher| watcher.tick_with(now(), &started)).unwrap_or_default();
        self.shield_look();
        // A reported program: where it is set to start again. Asked after the look, so nothing waits behind it.
        for case in cases.iter_mut().filter(|case| case.get("chain").is_some() && case.get("persistence").is_none()) {
            let path = case["path"].as_str().unwrap_or("").to_string();
            if path.is_empty() {
                continue;
            }
            if self.persistence.len() > 2000 {
                self.persistence.clear();
            }
            let found = self.persistence.entry(path.clone()).or_insert_with(|| crate::persist::find(&path));
            if !found.is_empty() {
                case["persistence"] = Value::Array(found.clone());
            }
        }
        cases
    }

    /// Wait for the next look: woken at once when a responder acted, otherwise after the usual pause.
    fn rest(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(TICK_SECONDS);
        while !STOP.load(Ordering::SeqCst) && Instant::now() < deadline {
            self.pump();
            let step = self.feeds.step_ms();
            match self.wake.recv_timeout(Duration::from_millis(step).min(deadline.saturating_duration_since(Instant::now()))) {
                Ok(()) => {
                    while self.wake.try_recv().is_ok() {}
                    self.woken = true;
                    return; // something was acted on: say so now
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => std::thread::sleep(Duration::from_millis(step)),
            }
        }
    }
}

fn say_case(case: &Value) {
    let (_, said) = local_line(case);
    println!("{said}");
    let acted = case["actions"].as_array().is_some_and(|list| !list.is_empty());
    if acted {
        // Why, in the agent's own words: labels only, never the command line.
        for signal in case["signals"].as_array().into_iter().flatten().filter(|signal| signal["points"].as_i64().unwrap_or(0) > 0) {
            println!("garrett:   because: {}", signal["evidence"].as_str().unwrap_or(""));
        }
        for action in case["actions"].as_array().into_iter().flatten() {
            println!("garrett:   {}", action["reason"].as_str().unwrap_or(""));
        }
    }
    match case["held"].as_str() {
        Some("learning") => println!("garrett:   left running: garrett is still learning this machine. Yours? garrett trust {0}   An attack? garrett confirm {0}", case["key"].as_str().unwrap_or("")),
        Some(_) => println!("garrett:   left running: it was here before garrett knew this machine. Yours? garrett trust {0}   An attack? garrett confirm {0}", case["key"].as_str().unwrap_or("")),
        None => {}
    }
    for step in case["cleanup"].as_array().into_iter().flatten() {
        println!("garrett:   {} {}: {}", step["action"].as_str().unwrap_or(""), step["kind"].as_str().unwrap_or(""), step["where"].as_str().unwrap_or(""));
    }
    if case["cleanup"].as_array().is_some_and(|list| !list.is_empty()) {
        println!("garrett:   undo all of it with: garrett restore {}", case["key"].as_str().unwrap_or(""));
    }
}

fn say_settling(running: &Running) {
    let left = running.watcher.lock().map(|watcher| watcher.settling(now()).0).unwrap_or(0.0);
    if left > 0.0 {
        println!("garrett: learning this machine for the next {:.0} hour(s): attacks are stopped as always; a program that only looks suspicious is reported and left for you to judge (garrett trust|confirm <case>)", (left / 3600.0).ceil());
    }
}

/// No service: watch this machine, act on what is hostile, and keep the cases here.
pub fn run_alone(state: &State, mode: &str, clean: bool) -> i32 {
    let mode = if agent::MODES.contains(&mode) { mode } else { "kill" };
    let Ok(salt) = agent::standalone_salt(state) else {
        eprintln!("garrett: the state folder {} cannot be written.", state.directory.display());
        return 1;
    };
    listen_for_stop();
    let mut running = build(state, &salt, if mode == "kill" { "kill" } else if mode == "report" { "report" } else { "pause" }, clean, false, 20.0, &[]);
    let (log, trusted_file, decisions) = (state.directory.join("cases.jsonl"), state.directory.join("trusted.json"), state.directory.join("decisions.json"));
    let mut said: std::collections::HashMap<String, (String, String)> = std::collections::HashMap::new();
    println!("garrett: watching this machine by itself (mode: {mode}). Join a fleet any time: garrett enroll --server <address> --key <key>");
    say_settling(&running);
    while !STOP.load(Ordering::SeqCst) {
        take_local(&running, state, true);
        if let Ok(mut watcher) = running.watcher.lock() {
            let trusted = std::fs::read(&trusted_file).ok().and_then(|raw| serde_json::from_slice::<Value>(&raw).ok()).unwrap_or_else(|| Value::Array(Vec::new()));
            watcher.set_trusted(&trusted);
            if let Some(wanted) = std::fs::read(&decisions).ok().and_then(|raw| serde_json::from_slice::<Value>(&raw).ok()) {
                let _ = std::fs::remove_file(&decisions);
                watcher.apply_commands(&wanted, now());
            }
        }
        let cases = running.look();
        let results = running.watcher.lock().map(|mut watcher| watcher.take_results()).unwrap_or_default();
        for result in results {
            println!("garrett: {} {} program(s) for case {}", result["action"].as_str().unwrap_or(""), result["programs"], result["key"].as_str().unwrap_or(""));
            for step in result["cleanup"].as_array().into_iter().flatten() {
                println!("garrett:   {} {}: {}", step["action"].as_str().unwrap_or(""), step["kind"].as_str().unwrap_or(""), step["where"].as_str().unwrap_or(""));
            }
        }
        for case in &cases {
            let key = case["key"].as_str().unwrap_or("").to_string();
            let acted: String = case["actions"].as_array().into_iter().flatten().filter_map(|action| action["action"].as_str()).collect();
            let mark = (case["level"].as_str().unwrap_or("").to_string(), acted);
            if said.get(&key) == Some(&mark) {
                continue;
            }
            said.insert(key, mark);
            let (line, _) = local_line(case);
            if std::fs::metadata(&log).map(|meta| meta.len() > 5 * 1024 * 1024).unwrap_or(false) {
                let _ = std::fs::rename(&log, state.directory.join("cases.old.jsonl"));
            }
            if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(&log) {
                use std::io::Write;
                let _ = writeln!(file, "{line}");
            }
            say_case(case);
            if let Ok(mut watcher) = running.watcher.lock() {
                watcher.mark_reported(std::slice::from_ref(case), now());
            }
        }
        running.rest();
    }
    if let Ok(mut watcher) = running.watcher.lock() {
        watcher.unblock();
    }
    0
}

fn service_addresses(server: &str) -> Vec<String> {
    use std::net::ToSocketAddrs;
    let authority = server.split_once("://").map(|(_, rest)| rest).unwrap_or(server);
    let with_port = if authority.rsplit_once(':').is_some_and(|(_, port)| port.bytes().all(|byte| byte.is_ascii_digit())) { authority.to_string() } else { format!("{authority}:443") };
    let mut found: Vec<String> = with_port.to_socket_addrs().map(|list| list.map(|address| address.ip().to_string()).collect()).unwrap_or_default();
    found.sort();
    found.dedup();
    found
}

/// Sample, score on the machine, report SUSPECT and HOSTILE cases, and carry out the operator's decisions.
/// Returns 2 when the service has removed this machine.
pub fn run(state: &State, saved: &Value, clean: bool) -> i32 {
    let text = |key: &str| saved[key].as_str().unwrap_or("").to_string();
    let (server, token, pin) = (text("server"), text("token"), text("pin"));
    let pin = (!pin.is_empty()).then_some(pin);
    let mode = saved["mode"].as_str().unwrap_or("report").to_string();
    listen_for_stop();
    let mut running = build(state, &text("salt"), &mode, clean, saved["fallback"] == "kill", saved["decide_after"].as_f64().unwrap_or(20.0), &service_addresses(&server));
    let clamp = |value: &Value, low: f64, high: f64, fallback: f64| value.as_f64().filter(|_| value.is_i64() || value.is_u64()).map(|number| number.clamp(low, high)).unwrap_or(fallback);
    let (mut interval, mut pulse) = (clamp(&saved["interval"], 60.0, 3600.0, 300.0), clamp(&saved["pulse"], 30.0, 600.0, 60.0));
    let (mut have, mut state_key) = (String::new(), text("state_key"));
    let (mut next_beat, mut fetch_at, mut send_after, mut failures, mut first) = (0.0f64, 0.0f64, 0.0f64, 0u32, true);
    let mut next_pulse = now() + pulse * jitter(0.5, 1.5);
    let mut pending: Vec<Value> = Vec::new();
    let mut results: Vec<Value> = Vec::new();
    // Which signals the service knows: it says so with the shared state. Until it does, only the first set.
    let mut signal_set = 1u64;

    // Apply whatever part of the shared state the service sent; an absent part means "you already have it".
    let take = |running: &Running, answer: &Value, have: &mut String, interval: &mut f64, pulse: &mut f64, state_key: &mut String| {
        if let Ok(mut watcher) = running.watcher.lock() {
            if answer.get("policy").is_some() {
                watcher.set_policy(&answer["policy"]);
            }
            if answer.get("shapes").is_some() {
                watcher.set_shapes(&answer["shapes"]);
            }
            if answer.get("watch").is_some() {
                watcher.set_watch(&answer["watch"]);
            }
            if answer.get("fleet").is_some() {
                watcher.set_fleet(&answer["fleet"]);
            }
        }
        if let (Some(revision), true) = (answer["revision"].as_str(), answer.get("fleet").is_some()) {
            *have = revision.chars().take(64).collect();
        }
        *interval = clamp(&answer["interval"], 60.0, 3600.0, *interval);
        *pulse = clamp(&answer["pulse"], 30.0, 600.0, *pulse);
        if let Some(key) = answer["state_key"].as_str().filter(|key| key.len() == 64 && key.bytes().all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())) {
            *state_key = key.to_string();
        }
    };

    while !STOP.load(Ordering::SeqCst) {
        let moment = now();
        if !state_key.is_empty() && moment >= next_pulse {
            next_pulse = moment + pulse * jitter(0.85, 1.15);
            if let Ok(beat) = call(&server, "/v1/pulse", None, None, pin.as_deref()) {
                if beat["revision"].as_str().is_some_and(|revision| revision != have) && fetch_at == 0.0 {
                    fetch_at = moment + jitter(0.0, pulse.min(60.0)); // something changed: fetch it, but not all at once
                }
            }
        }
        if fetch_at > 0.0 && moment >= fetch_at {
            fetch_at = 0.0;
            if let Ok(answer) = call(&server, "/v1/state", None, Some(&state_key), pin.as_deref()) {
                signal_set = answer["signals"].as_u64().unwrap_or(signal_set);
                take(&running, &answer, &mut have, &mut interval, &mut pulse, &mut state_key);
            }
        }
        for case in running.look() {
            let Some(case) = agent::known_to(case, signal_set) else { continue };
            if case["actions"].as_array().is_some_and(|list| !list.is_empty()) {
                send_after = 0.0; // something was paused or stopped: say so now, not at the next window
            }
            match pending.iter_mut().find(|known| known["key"] == case["key"]) {
                Some(known) => *known = case,
                None => pending.push(case),
            }
        }
        if let Ok(mut watcher) = running.watcher.lock() {
            results.extend(watcher.take_results());
        }
        if now() >= send_after && (!pending.is_empty() || !results.is_empty() || first || now() >= next_beat) {
            let mut cases = pending.clone();
            cases.sort_by(|a, b| b["score"].as_i64().cmp(&a["score"].as_i64()));
            cases.truncate(MAX_CASES_PER_REPORT);
            let sending: Vec<Value> = results.iter().take(16).cloned().collect();
            let payload = running.watcher.lock().map(|mut watcher| {
                let (status, exits, mesh) = (watcher.status(), watcher.exits_revision().to_string(), watcher.mesh(now(), agent::privileged()));
                agent::report_payload(machine::SYSTEM, &cases, &status, &sending, &exits, &mesh, &have)
            });
            let answer = match payload {
                Ok(payload) => call(&server, "/v1/report", Some(&payload), Some(&token), pin.as_deref()),
                Err(_) => Err(CallError::Other("the watcher is not available".into())),
            };
            match answer {
                Ok(answer) if answer["protocol"] == agent::PROTOCOL && answer["accepted"] == true => {
                    signal_set = answer["signals"].as_u64().unwrap_or(signal_set);
                    take(&running, &answer, &mut have, &mut interval, &mut pulse, &mut state_key);
                    let waiting = running.watcher.lock().map(|mut watcher| {
                        watcher.mark_reported(&cases, now());
                        watcher.set_trusted(&answer["trusted"]);
                        watcher.set_exits(&answer["exits"]);
                        watcher.apply_commands(&answer["commands"], now());
                        watcher.results_waiting()
                    }).unwrap_or(false);
                    next_beat = now() + interval * jitter(0.85, 1.15);
                    results.drain(..sending.len());
                    pending.retain(|known| !cases.iter().any(|sent| sent["key"] == known["key"]));
                    failures = 0;
                    first = false;
                    send_after = now() + if waiting { 5.0 } else { 30.0 };
                }
                Err(CallError::Status(401)) => {
                    // The device was removed on the service, so no decision can reach it any more: whatever this
                    // agent paused is let continue rather than left frozen for good.
                    if let Ok(mut watcher) = running.watcher.lock() {
                        watcher.release_all(now());
                        watcher.unblock();
                    }
                    return 2;
                }
                other => {
                    if failures == 0 {
                        // Said once for each run of failures, so the machine's own log shows why reports stopped.
                        match other {
                            Err(why) => eprintln!("garrett: the report did not reach the service: {why}"),
                            Ok(_) => eprintln!("garrett: the service did not accept the report."),
                        }
                    }
                    failures += 1;
                    send_after = now() + (30.0 * 2f64.powi(failures.min(5) as i32)).min(900.0) * jitter(0.7, 1.3); // never retry in step with the rest of the fleet
                }
            }
        }
        running.rest();
    }
    if let Ok(mut watcher) = running.watcher.lock() {
        watcher.unblock();
    }
    0
}

/// Let every program this agent paused continue. Used when the machine leaves its service.
pub fn let_go(state: &State) -> usize {
    if !state.directory.join("sentinel-paused.json").exists() {
        return 0;
    }
    let looked: Shared = Arc::new(Mutex::new(Looked::default()));
    machine::refresh_now(&looked);
    let mut watcher = Watcher::new(machine::sensor(looked), Some(RealHands::default()), &"0".repeat(64), Mode::Pause, &machine::system_root());
    watcher.own.insert(std::process::id());
    watcher.keep_in(&state.directory, false);
    watcher.release_all(now())
}
