//! What every system's glue shares: running one fixed operating-system query, and the answers a full look works
//! from. The slow questions are asked outside the watcher's lock, so a responder never waits behind them.

use crate::linux::Snap;
use crate::parse::{Conn, Proc};
use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::process::{Command, Stdio};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Run one fixed operating-system query: no shell, bounded output, enforced timeout. `None` when it fails.
pub fn run(arguments: &[&str], input: Option<&[u8]>, timeout: Duration) -> Option<String> {
    let mut command = Command::new(arguments[0]);
    command.args(&arguments[1..]).stdin(if input.is_some() { Stdio::piped() } else { Stdio::null() }).stdout(Stdio::piped()).stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0800_0000); // no console window
    }
    let mut child = command.spawn().ok()?;
    if let (Some(bytes), Some(mut pipe)) = (input, child.stdin.take()) {
        use std::io::Write;
        let _ = pipe.write_all(bytes);
    }
    let mut pipe = child.stdout.take()?;
    let reader = std::thread::spawn(move || {
        let mut out = Vec::new();
        let _ = pipe.by_ref().take(2 * 1024 * 1024).read_to_end(&mut out);
        out
    });
    let started = Instant::now();
    let status = loop {
        match child.try_wait().ok()? {
            Some(status) => break status,
            None if started.elapsed() > timeout => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
            None => std::thread::sleep(Duration::from_millis(5)),
        }
    };
    let out = reader.join().ok()?;
    status.success().then(|| String::from_utf8_lossy(&out).trim().to_string())
}

/// What the last full look saw.
#[derive(Default)]
pub struct Looked {
    pub procs: Vec<Proc>,
    pub conns: Vec<Conn>,
    pub listening: HashSet<u32>,
    /// Programs that listen in a network of their own (containers), asked for on a thread of its own.
    pub elsewhere: HashSet<u32>,
}

/// What the last full look saw, shared with the sensor.
pub type Shared = Arc<Mutex<Looked>>;

/// Notice a program start within a few milliseconds where the system offers no notice this agent can take
/// without a driver (Windows, macOS): ask for the list of running programs many times a second, which is one
/// cheap call, and read only the ones that were not there the time before. It only looks; nothing waits on it.
///
/// `forks`: a new process is first a copy of its parent and only then becomes itself (macOS, as on any Unix), so
/// one still wearing its parent's name is looked at again for a few rounds before it is reported.
pub fn watch_starts(pids: fn() -> HashSet<u32>, snapshot: fn(u32) -> Option<Snap>, forks: bool, starts: Sender<Snap>) {
    let _ = std::thread::Builder::new().name("garrett-starts".into()).spawn(move || {
        let own = std::process::id();
        let mut known = pids();
        let mut waiting: HashMap<u32, u32> = HashMap::new();
        loop {
            std::thread::sleep(Duration::from_millis(4));
            let now = pids();
            if now.is_empty() {
                continue;
            }
            let mut fresh: Vec<u32> = now.difference(&known).copied().collect();
            fresh.sort_unstable();
            fresh.truncate(64);
            known = now;
            waiting.retain(|pid, _| known.contains(pid));
            let mut again: Vec<u32> = waiting.keys().copied().collect();
            again.sort_unstable();
            for pid in fresh.into_iter().chain(again) {
                if pid == own {
                    continue;
                }
                let snap = snapshot(pid);
                let rounds = waiting.get(&pid).copied().unwrap_or(0);
                // Not yet the program it is about to become, or so new that the system cannot say what it is
                // yet: looked at again for a few rounds, never dropped while it is still running.
                let early = match &snap {
                    Some(snap) => (forks && snap.proc.name == snap.parent) || snap.cmdline.is_empty(),
                    None => true,
                };
                if early && rounds < 6 {
                    waiting.insert(pid, rounds + 1);
                    continue;
                }
                waiting.remove(&pid);
                if let Some(snap) = snap {
                    if starts.send(snap).is_err() {
                        return;
                    }
                }
            }
        }
    });
}
