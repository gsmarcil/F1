//! The rest of the watcher: what it keeps between runs, what the service tells it, the decisions it carries out on
//! programs it froze, cleaning up after a stop, and startup entries that appear while it watches.

use super::{protected, Hands, Identity, Mode, Sensor, Watcher};
use crate::linux::Snap;
use crate::net;
use crate::parse::Proc;
use crate::score::{clean, level_for, risky_commands, score_process, View, ADVISORY_ADDRESSES, WEB_SERVER_PREFIXES};
use regex::Regex;
use serde_json::{json, Map, Value};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

pub(crate) struct Contained {
    pub members: Vec<Identity>,
    pub at: f64,
    pub name: String,
    pub held: bool,
}

#[derive(Default)]
pub(crate) struct More {
    pub directory: Option<PathBuf>,
    pub contained: Vec<(String, Contained)>,
    pub adopting: Vec<(String, Contained)>,
    pub contained_saved: bool,
    pub results: Vec<Value>,
    pub fallback_kill: bool,
    pub decide_after: f64,
    pub watch: HashMap<String, String>,
    pub exits_revision: String,
    pub addresses: HashMap<String, f64>,
    pub peers: HashMap<(String, u32, &'static str), f64>,
    pub never_block: HashSet<String>,
    pub blocked: Option<Vec<String>>,
    pub block_failed: bool,
    pub cleanups: HashMap<String, Vec<Value>>,
    /// Programs a responder ended at the event, to clean up after at the next look: (case, the programs, where each lived, since when).
    pub after_event: Vec<(String, Vec<Proc>, HashMap<Identity, String>, f64)>,
    pub extra: Vec<Value>,
    /// Privilege escalations said at the moment they were seen, by case, and when.
    pub escalations: HashMap<String, f64>,
    /// When a keyboard this machine had never seen was last plugged in.
    pub keyboard_at: f64,
    pub seen: (usize, usize),
    pub process_feed: bool,
    pub clean_up: bool,
    pub web: Option<crate::web::WebWatch>,
    pub web_at: f64,
    pub ledger_saved: f64,
    #[cfg(unix)]
    pub startup: Option<crate::clean::StartupWatch>,
    #[cfg(windows)]
    pub startup: Option<crate::startup_win::StartupWatch>,
    #[cfg(windows)]
    pub startup_at: f64,
    /// Addresses whose successful sign-in after a burst of failures has been said.
    pub signin_said: HashSet<String>,
    /// The addresses the service asked every machine to refuse.
    pub fleet_block: Vec<String>,
    /// The case of each service a stopped shell came through: (the case, when, the service's name), by process.
    pub attacks: HashMap<u32, (Value, f64, String)>,
    /// The case of each web client that attacked, by address.
    pub web_attacks: HashMap<String, (Value, f64)>,
    /// Addresses an attacked service called back: (until when, the case, whether this agent refuses it).
    pub callouts: HashMap<String, (f64, String, bool)>,
    /// Tracker addresses the privacy shield refuses.
    pub shield_block: Vec<String>,
    /// Until when this agent is still learning the machine it was just installed on.
    pub settle_until: f64,
    /// Cases met while settling in that only their score spoke against: left running until the owner judges them.
    pub held: HashSet<String>,
    /// Cases the owner confirmed as attacks: never left running.
    pub confirmed: HashSet<String>,
    /// Why a case was left running at this look, to be said with it.
    pub left: HashMap<String, &'static str>,
}

fn is_key(key: &str) -> bool {
    key.len() == 32 && key.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn signal_name(name: &str) -> bool {
    (3..=40).contains(&name.len()) && name.bytes().all(|byte| byte.is_ascii_lowercase() || byte == b'_')
}

fn startup_drop() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| Regex::new(r#"(?:/tmp/|/var/tmp/|/dev/shm/|/private/tmp/|/private/var/tmp/)[^\s"'`;|&()<>]+"#).expect("a fixed pattern"))
}

fn write_private(path: &Path, body: &str) {
    let temporary = path.with_extension("tmp");
    if std::fs::write(&temporary, body).is_ok() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o600));
        }
        let _ = std::fs::rename(&temporary, path);
    }
}

impl<S: Sensor, H: Hands> Watcher<S, H> {
    /// Give the watcher its folder: what it froze, learned and cleaned is kept there between runs, and (on Linux
    /// and macOS) cleanup and the startup watch are switched on.
    pub fn keep_in(&mut self, directory: &Path, clean_up: bool) {
        self.more.directory = Some(directory.to_path_buf());
        self.more.clean_up = clean_up;
        self.more.adopting = self.load_contained();
        self.load_ledger();
        self.load_habits();
        #[cfg(unix)]
        if self.sensor.system() != "windows" {
            self.more.startup = Some(crate::clean::StartupWatch::new(self.sensor.system(), directory, None));
        }
        #[cfg(windows)]
        {
            self.more.startup = Some(crate::startup_win::StartupWatch::new(directory));
        }
    }

    /// Start, or carry on, the settling-in period of a fresh install. For that long the agent acts only on what
    /// is unmistakably an attack (the chains in `score::containment_reason`). A program that only its score
    /// speaks against is reported and left running, then and afterwards, until the owner says what it is: such a
    /// program was on the machine before the agent knew it, and may be the owner's own.
    /// `fresh` is false for an install that has run before this version: it does not settle in again.
    pub fn settle_in(&mut self, hours: f64, fresh: bool, now: f64) {
        let Some(path) = self.file("settled.json") else { return };
        match std::fs::read(&path).ok().and_then(|raw| serde_json::from_slice::<Value>(&raw).ok()) {
            Some(kept) => {
                self.more.settle_until = kept["until"].as_f64().unwrap_or(0.0);
                self.more.held = kept["held"].as_array().into_iter().flatten().filter_map(Value::as_str).filter(|key| is_key(key)).map(str::to_string).collect();
            }
            None => {
                self.more.settle_until = if fresh && hours > 0.0 { now + hours.min(24.0 * 30.0) * 3600.0 } else { 0.0 };
                self.save_settled();
            }
        }
    }

    fn save_settled(&self) {
        if let Some(path) = self.file("settled.json") {
            let mut held: Vec<&String> = self.more.held.iter().collect();
            held.sort();
            write_private(&path, &json!({"until": self.more.settle_until, "held": held}).to_string());
        }
    }

    /// The cases the owner confirmed as attacks.
    pub fn set_confirmed(&mut self, keys: &Value) {
        self.more.confirmed = keys.as_array().into_iter().flatten().filter_map(Value::as_str).filter(|key| is_key(key)).map(str::to_string).collect();
    }

    /// (seconds of settling in left, how many programs are left running for the owner to judge).
    pub fn settling(&self, now: f64) -> (f64, usize) {
        ((self.more.settle_until - now).max(0.0), self.more.held.iter().filter(|key| !self.more.confirmed.contains(*key) && !self.trusted.contains(*key)).count())
    }

    /// True when this program is to be left running although it would be stopped: nothing but its score speaks
    /// against it, and it was met while the agent was settling in.
    pub(crate) fn held_back(&mut self, key: &str, reason: &str, now: f64) -> bool {
        if !reason.starts_with("it reached the hostile level") || self.more.confirmed.contains(key) {
            return false;
        }
        if now < self.more.settle_until {
            if self.more.held.len() < 2000 && self.more.held.insert(key.to_string()) {
                self.save_settled();
            }
            self.more.left.insert(key.to_string(), "learning");
            return true;
        }
        if self.more.held.contains(key) {
            self.more.left.insert(key.to_string(), "here first");
            return true;
        }
        false
    }

    pub fn decide_with(&mut self, fallback_kill: bool, decide_after: f64) {
        self.more.fallback_kill = fallback_kill;
        self.more.decide_after = decide_after.max(5.0);
    }

    pub fn never_block(&mut self, addresses: &[String]) {
        self.more.never_block = addresses.iter().cloned().collect();
    }

    pub fn set_process_feed(&mut self, open: bool) {
        self.more.process_feed = open;
    }

    // ------------------------------------------------------------ kept between runs

    fn file(&self, name: &str) -> Option<PathBuf> {
        self.more.directory.as_ref().map(|directory| directory.join(name))
    }

    fn load_contained(&self) -> Vec<(String, Contained)> {
        let Some(path) = self.file("sentinel-paused.json") else { return Vec::new() };
        let plain = std::fs::symlink_metadata(&path).map(|meta| !meta.file_type().is_symlink() && meta.len() < 200_000).unwrap_or(false);
        let Some(value) = plain.then(|| std::fs::read(&path).ok()).flatten().and_then(|raw| serde_json::from_slice::<Value>(&raw).ok()) else { return Vec::new() };
        let mut found = Vec::new();
        for (key, entry) in value.as_object().cloned().unwrap_or_default() {
            let Some(list) = entry["members"].as_array() else { continue };
            let members: Vec<Identity> = list.iter().filter_map(|member| Some((member.get(0)?.as_u64()? as u32, member.get(1)?.as_f64()? as u64))).collect();
            if is_key(&key) && members.len() == list.len() {
                found.push((key, Contained { members, at: entry["at"].as_f64().unwrap_or(0.0), name: clean(entry["name"].as_str().unwrap_or(""), 80), held: entry["held"].as_bool().unwrap_or(false) }));
            }
        }
        found
    }

    pub(crate) fn save_contained(&mut self) {
        let Some(path) = self.file("sentinel-paused.json") else { return };
        if self.more.contained.is_empty() {
            let _ = std::fs::remove_file(&path);
            self.more.contained_saved = false;
            return;
        }
        let all: Map<String, Value> = self.more.contained.iter().map(|(key, entry)| (key.clone(), json!({"members": entry.members.iter().map(|(pid, started)| json!([pid, started])).collect::<Vec<_>>(), "at": entry.at, "name": entry.name, "held": entry.held}))).collect();
        write_private(&path, &Value::Object(all).to_string());
        self.more.contained_saved = path.exists();
    }

    fn load_ledger(&mut self) {
        let Some(value) = self.file("sentinel-baseline.json").and_then(|path| std::fs::read(path).ok()).and_then(|raw| serde_json::from_slice::<Value>(&raw).ok()) else { return };
        for (key, entry) in value.as_object().cloned().unwrap_or_default() {
            let remotes: Vec<String> = entry["remotes"].as_array().map(|list| list.iter().filter_map(|item| item.as_str().map(str::to_string)).collect()).unwrap_or_default();
            if key == "#detections" {
                self.detections_seen = remotes.into_iter().collect();
            } else if let Some(first) = entry["first"].as_f64() {
                self.ledger.insert(key, super::LedgerEntry { first, last: entry["last"].as_f64().unwrap_or(first), remotes });
            }
        }
    }

    fn save_ledger(&mut self) {
        let Some(path) = self.file("sentinel-baseline.json") else { return };
        let mut entries: Vec<(&String, &super::LedgerEntry)> = self.ledger.iter().collect();
        entries.sort_by(|a, b| b.1.last.partial_cmp(&a.1.last).unwrap_or(std::cmp::Ordering::Equal));
        let mut all: Map<String, Value> = entries.into_iter().take(2000).map(|(key, entry)| (key.clone(), json!({"first": entry.first, "last": entry.last, "remotes": entry.remotes}))).collect();
        let mut seen: Vec<&String> = self.detections_seen.iter().collect();
        seen.sort();
        all.insert("#detections".into(), json!({"first": 0, "last": 0, "remotes": seen[seen.len().saturating_sub(500)..]}));
        write_private(&path, &Value::Object(all).to_string());
    }

    fn load_habits(&mut self) {
        let Some(value) = self.file("sentinel-habits.json").and_then(|path| std::fs::read(path).ok()).and_then(|raw| serde_json::from_slice::<Value>(&raw).ok()) else { return };
        for (name, shapes) in value.as_object().cloned().unwrap_or_default() {
            if let Some(list) = shapes.as_array() {
                self.habits.insert(name, list.iter().filter_map(|item| item.as_str().map(str::to_string)).collect());
            }
        }
    }

    fn save_habits(&self) {
        let Some(path) = self.file("sentinel-habits.json") else { return };
        let all: Map<String, Value> = self.habits.iter().take(300).map(|(name, shapes)| {
            let mut list: Vec<&String> = shapes.iter().collect();
            list.sort();
            list.truncate(300);
            (name.clone(), json!(list))
        }).collect();
        write_private(&path, &Value::Object(all).to_string());
    }

    /// Called from the full look: write down what was learned, every ten minutes or when asked to at once.
    pub(crate) fn keep(&mut self, now: f64) {
        if now - self.more.ledger_saved >= 600.0 {
            self.more.ledger_saved = now;
            self.save_ledger();
            self.save_habits();
        }
    }

    // ------------------------------------------------------------ programs this agent froze

    pub(crate) fn remember_paused(&mut self, key: &str, done: &[Identity], name: &str, now: f64) {
        match self.more.contained.iter_mut().find(|(known, _)| known == key) {
            Some((_, entry)) => entry.members.extend(done),
            None => self.more.contained.push((key.to_string(), Contained { members: done.to_vec(), at: now, name: name.to_string(), held: false })),
        }
        self.save_contained();
    }

    /// Take up again the programs an earlier run of this agent paused, if they are still the same processes.
    pub(crate) fn adopt(&mut self, procs: &[Proc], now: f64) {
        let waiting = std::mem::take(&mut self.more.adopting);
        for (key, entry) in waiting {
            let members: Vec<Identity> = entry.members.iter().copied().filter(|(pid, started)| procs.iter().any(|proc| proc.pid == *pid && proc.started == *started)).collect();
            if members.is_empty() || self.more.contained.iter().any(|(known, _)| *known == key) {
                continue;
            }
            match self.hands.as_mut() {
                None => continue, // this agent may no longer act: `let_go` releases them
                Some(_) => {
                    self.paused.extend(members.iter().copied());
                    self.more.contained.push((key, Contained { members, at: if entry.at > 0.0 { entry.at } else { now }, name: entry.name, held: entry.held }));
                }
            }
        }
        self.save_contained();
    }

    /// Stop or release what this agent paused under one case. Only the exact processes it paused.
    fn settle(&mut self, key: &str, stop: bool, procs: &[Proc], fallback: bool, now: f64) {
        let Some(at) = self.more.contained.iter().position(|(known, _)| known == key) else { return };
        let (_, entry) = self.more.contained.remove(at);
        // A recycled process id is skipped.
        let mut members: Vec<Proc> = entry.members.iter().filter_map(|(pid, started)| procs.iter().find(|proc| proc.pid == *pid && proc.started == *started).cloned()).filter(|proc| !protected(proc, &self.own)).collect();
        let spaces = if stop { self.spaces(&members) } else { HashMap::new() };
        if stop {
            members.reverse();
        }
        let done = match self.hands.as_mut() {
            Some(hands) => members.iter().filter(|proc| if stop { hands.kill(proc.pid) } else { hands.resume(proc.pid) }).count(),
            None => 0,
        };
        for identity in &entry.members {
            self.paused.remove(identity);
        }
        if !stop {
            self.released.extend(entry.members.iter().copied()); // judged ordinary: these exact processes are left alone from now on
        }
        self.save_contained();
        let mut result = json!({"key": key, "action": if stop { "stopped" } else { "released" }, "programs": done, "gone": entry.members.len() - members.len()});
        if stop {
            let steps = self.clean_after(key, &members, procs, &[], entry.at, &spaces, now);
            if !steps.is_empty() {
                result["cleanup"] = json!(steps);
            }
        }
        if fallback {
            result["fallback"] = json!(true);
        }
        self.more.results.push(result);
    }

    /// The decision on a program this agent paused: stop it, let it continue, or keep holding it for a person.
    pub fn apply_commands(&mut self, commands: &Value, now: f64) {
        let Some(list) = commands.as_array() else { return };
        if self.hands.is_none() {
            return;
        }
        let procs = self.sensor.running_now();
        if !self.more.adopting.is_empty() {
            self.adopt(&procs, now);
        }
        for command in list.iter().take(16) {
            let (Some(key), Some(action)) = (command["key"].as_str(), command["action"].as_str()) else { continue };
            let Some(at) = self.more.contained.iter().position(|(known, _)| known == key) else { continue };
            match action {
                "hold" => {
                    self.more.contained[at].1.held = true; // the service answered: a person will decide, so the fallback does not apply
                    self.save_contained();
                }
                "stop" | "release" => self.settle(key, action == "stop", &procs, false, now),
                _ => {}
            }
        }
    }

    /// decide mode with fallback "kill": the service gave no answer in time, so the hostile program is ended.
    pub(crate) fn fallback(&mut self, procs: &[Proc], now: f64) {
        if self.mode != Mode::Decide || !self.more.fallback_kill {
            return;
        }
        let due: Vec<String> = self.more.contained.iter().filter(|(_, entry)| !entry.held && now - entry.at >= self.more.decide_after).map(|(key, _)| key.clone()).collect();
        for key in due {
            self.settle(&key, true, procs, true, now);
        }
    }

    /// Another garrett command on this machine let the frozen programs go: they are no longer this agent's to decide.
    pub(crate) fn notice_let_go(&mut self) {
        if self.more.contained.is_empty() || !self.more.contained_saved || self.file("sentinel-paused.json").is_some_and(|path| path.exists()) {
            return;
        }
        for (_, entry) in std::mem::take(&mut self.more.contained) {
            for identity in entry.members {
                self.paused.remove(&identity);
                self.released.insert(identity);
            }
        }
        self.more.contained_saved = false;
    }

    /// Let every program this agent paused continue: its service removed it, or it is leaving its service.
    /// Returns how many cases were let go.
    pub fn release_all(&mut self, now: f64) -> usize {
        let procs = self.sensor.running_now();
        if !self.more.adopting.is_empty() {
            self.adopt(&procs, now);
        }
        let keys: Vec<String> = self.more.contained.iter().map(|(key, _)| key.clone()).collect();
        for key in &keys {
            self.settle(key, false, &procs, false, now);
        }
        keys.len()
    }

    /// What was decided on frozen programs since the last report, sixteen at a time.
    pub fn take_results(&mut self) -> Vec<Value> {
        let count = self.more.results.len().min(16);
        self.more.results.drain(..count).collect()
    }

    pub fn results_waiting(&self) -> bool {
        !self.more.results.is_empty()
    }

    // ------------------------------------------------------------ the web server's own log

    /// Watch the web server's access logs and web folders as well.
    pub fn set_web(&mut self, web: Option<crate::web::WebWatch>) {
        self.more.web = web;
    }

    /// Attacks seen in the web server's access log, and server-side scripts that appeared in a web folder.
    pub(crate) fn web_cases(&mut self, now: f64) -> Vec<Value> {
        let Some(web) = self.more.web.as_mut() else { return Vec::new() };
        let (clients, scripts) = web.poll(now);
        let mut cases = Vec::new();
        let rank = |level: &str| super::LEVELS.iter().position(|known| *known == level).unwrap_or(0);
        let mut emit = |watcher: &Self, key: String, name: String, path: String, signals: Vec<Value>, remotes: Vec<Value>| {
            let score: i64 = signals.iter().filter_map(|signal| signal["points"].as_i64()).sum();
            let categories: std::collections::BTreeSet<String> = signals.iter().filter_map(|signal| signal["category"].as_str().map(str::to_string)).collect();
            let level = level_for(score, categories.len());
            let previous = watcher.reported.get(&key);
            let worse = previous.is_some_and(|before| rank(level) > rank(&before.0) || score >= before.2 + 2);
            if (level == "SUSPECT" || level == "HOSTILE") && !watcher.trusted.contains(&key) && (previous.is_none() || worse || previous.is_some_and(|before| now - before.1 >= 6.0 * 3600.0)) {
                cases.push(json!({"key": key, "level": level, "score": score, "name": name, "path": path, "parent": "", "categories": categories,
                    "signals": signals, "remotes": remotes, "first_seen": now.trunc() as i64, "observed_at": now.trunc() as i64}));
            }
        };
        for (client, marks) in clients {
            let mut signals: Vec<Value> = Vec::new();
            for (signal, base, said) in marks {
                let points = (base + self.policy.get(signal).copied().unwrap_or(0)).clamp(0, 9);
                if points > 0 {
                    signals.push(json!({"id": signal, "points": points, "category": "web", "evidence": clean(&format!("This web client {said}."), 200)}));
                }
            }
            let address = crate::parse::plain_address(&client);
            if !signals.is_empty() && self.exits.contains(&address) {
                signals.push(json!({"id": "inbound_tor_exit", "points": 2, "category": "inbound", "evidence": "These requests came from a Tor exit node."}));
            }
            if ADVISORY_ADDRESSES.contains(&address.as_str()) {
                signals.push(json!({"id": "inbound_advisory_indicator", "points": 5, "category": "inbound",
                    "evidence": clean(&format!("The web server answered requests from {client}, listed in {}. The address may have been reassigned since; review before acting.", crate::score::ADVISORY), 200)}));
            }
            if !signals.is_empty() {
                let plain = !address.is_empty() && address.chars().all(|letter| letter.is_ascii_hexdigit() || letter == ':' || letter == '.');
                let remotes = if plain { vec![json!({"address": address, "port": 0, "names": [], "direction": "in"})] } else { Vec::new() };
                emit(self, self.digest(&format!("web:{client}")), format!("Web client {}", clean(&client, 60)), String::new(), signals, remotes);
            }
        }
        for path in scripts.iter().take(4) {
            let name = path.rsplit(['/', '\\']).next().unwrap_or("");
            emit(self, self.digest(&format!("webfile:{}", path.to_lowercase())), clean(name, 80), clean(path, 300),
                vec![json!({"id": "web_shell_file", "points": 5, "category": "web", "evidence": "A new server-side script appeared in a web folder after Sentinel started, with no release around it."})], Vec::new());
        }
        cases
    }

    // ------------------------------------------------------------ cleaning up after a stop

    /// The files in a temporary folder that a stopped program's command line names. They are cleaned up with it:
    /// frozen at its first instruction it has started nothing yet, and what it was about to run is all there is.
    pub(crate) fn named_files(proc: &Proc, cmdline: &str) -> Vec<Proc> {
        let found: std::collections::BTreeSet<&str> = startup_drop().find_iter(cmdline).map(|found| found.as_str()).collect();
        found.into_iter().take(8).map(|path| Proc { path: path.to_string(), ..proc.clone() }).collect()
    }

    /// Clean up after what responders ended at the event. Done at the look, not by the responder: a responder
    /// only ever freezes and ends, so the next program start never waits behind file work.
    pub(crate) fn clean_after_events(&mut self, procs: &[Proc], now: f64) {
        for (key, members, spaces, since) in std::mem::take(&mut self.more.after_event) {
            let steps = self.clean_after(&key, &members, procs, &[], since, &spaces, now);
            if !steps.is_empty() {
                let known = self.more.cleanups.entry(key).or_default();
                known.extend(steps);
                known.truncate(12);
            }
        }
    }

    /// Which file system each of these programs lives in, read before they are stopped: a program in a container
    /// sees its own files, and its paths mean nothing on this machine.
    pub(crate) fn spaces(&mut self, members: &[Proc]) -> HashMap<Identity, String> {
        members.iter().filter_map(|proc| self.sensor.mount_space(proc.pid).map(|space| ((proc.pid, proc.started), space))).collect()
    }

    #[cfg(unix)]
    fn cleaner(&self) -> Option<crate::clean::Cleaner> {
        let directory = self.more.directory.as_ref()?;
        (self.more.clean_up && self.hands.is_some() && self.sensor.system() != "windows").then(|| crate::clean::Cleaner::new(self.sensor.system(), directory, None, false))
    }

    #[cfg(unix)]
    fn clean_paths(&mut self, key: &str, paths: &[String], procs: &[Proc], addresses: &[String], since: f64, stopped: &HashSet<Identity>, now: f64) -> Vec<Value> {
        let Some(cleaner) = self.cleaner() else { return Vec::new() };
        let files = cleaner.removable(paths);
        // Another running copy of a file about to be taken away is ended first.
        let copies: Vec<u32> = procs.iter().filter(|proc| !proc.path.is_empty() && files.contains(&proc.path) && !stopped.contains(&(proc.pid, proc.started)) && !protected(proc, &self.own)).map(|proc| proc.pid).collect();
        let ended = match self.hands.as_mut() {
            Some(hands) => copies.into_iter().filter(|pid| hands.kill(*pid)).count(),
            None => 0,
        };
        let mut steps = if ended > 0 { vec![json!({"action": "ended", "kind": "another running copy", "where": format!("{ended} program(s)")})] } else { Vec::new() };
        steps.extend(cleaner.clean(key, &files, addresses, since, now));
        steps
    }

    /// Clean up after programs this agent has just stopped: their files, what would start them again, and the
    /// same inside a container when that is where they ran.
    #[cfg(unix)]
    pub(crate) fn clean_after(&mut self, key: &str, members: &[Proc], procs: &[Proc], addresses: &[String], since: f64, spaces: &HashMap<Identity, String>, now: f64) -> Vec<Value> {
        if self.cleaner().is_none() {
            return Vec::new();
        }
        let mine = if spaces.is_empty() { None } else { self.sensor.mount_space(std::process::id()) };
        let stopped: HashSet<Identity> = members.iter().map(|proc| (proc.pid, proc.started)).collect();
        let home = |proc: &Proc| spaces.get(&(proc.pid, proc.started)).cloned().or_else(|| mine.clone());
        let here: Vec<String> = members.iter().filter(|proc| !proc.path.is_empty() && home(proc) == mine).map(|proc| proc.path.clone()).collect();
        let mut steps = self.clean_paths(key, &here, procs, addresses, since, &stopped, now);
        let mut elsewhere: Vec<(String, Vec<String>)> = Vec::new();
        for proc in members.iter().filter(|proc| !proc.path.is_empty()) {
            let Some(space) = home(proc).filter(|space| Some(space) != mine.as_ref()) else { continue };
            match elsewhere.iter_mut().find(|(known, _)| *known == space) {
                Some((_, paths)) => paths.push(proc.path.clone()),
                None => elsewhere.push((space, vec![proc.path.clone()])),
            }
        }
        for (space, paths) in elsewhere {
            // The container's files are reached through any program still running in it.
            let anchor = procs.iter().find(|proc| !stopped.contains(&(proc.pid, proc.started)) && self.sensor.mount_space(proc.pid).as_deref() == Some(space.as_str())).map(|proc| proc.pid);
            let (Some(anchor), Some(directory)) = (anchor, self.more.directory.clone()) else { continue }; // the container ended with the program: its files went with it
            let root = PathBuf::from(format!("/proc/{anchor}/root"));
            let inner = crate::clean::Cleaner::new(self.sensor.system(), &directory, Some(&root), true);
            let mut whole: Vec<String> = paths.iter().map(|path| format!("{}{path}", inner.prefix)).collect();
            whole.sort();
            steps.extend(inner.clean(key, &whole, addresses, since, now));
        }
        steps.truncate(12);
        steps
    }

    /// Clean up after programs this agent has just stopped: their files, and what would start them again.
    #[cfg(windows)]
    pub(crate) fn clean_after(&mut self, key: &str, members: &[Proc], procs: &[Proc], addresses: &[String], _since: f64, _spaces: &HashMap<Identity, String>, now: f64) -> Vec<Value> {
        let Some(directory) = self.more.directory.clone().filter(|_| self.more.clean_up && self.hands.is_some()) else { return Vec::new() };
        let cleaner = crate::clean_win::Cleaner::new(&directory);
        let paths: Vec<String> = members.iter().filter(|proc| !proc.path.is_empty()).map(|proc| proc.path.clone()).collect();
        let wanted: HashSet<String> = cleaner.removable(&paths).iter().map(|path| path.to_lowercase()).collect();
        let stopped: HashSet<Identity> = members.iter().map(|proc| (proc.pid, proc.started)).collect();
        // Another running copy of a file about to be taken away is ended first.
        let copies: Vec<u32> = procs.iter().filter(|proc| !proc.path.is_empty() && wanted.contains(&proc.path.to_lowercase()) && !stopped.contains(&(proc.pid, proc.started)) && !protected(proc, &self.own)).map(|proc| proc.pid).collect();
        let ended = match self.hands.as_mut() {
            Some(hands) => copies.into_iter().filter(|pid| hands.kill(*pid)).count(),
            None => 0,
        };
        let mut steps = if ended > 0 { vec![json!({"action": "ended", "kind": "another running copy", "where": format!("{ended} program(s)")})] } else { Vec::new() };
        steps.extend(cleaner.clean(key, &paths, addresses, now));
        steps.truncate(12);
        steps
    }

    #[cfg(not(any(unix, windows)))]
    pub(crate) fn clean_after(&mut self, _key: &str, _members: &[Proc], _procs: &[Proc], _addresses: &[String], _since: f64, _spaces: &HashMap<Identity, String>, _now: f64) -> Vec<Value> {
        Vec::new()
    }

    pub(crate) fn known_bad(&self, addresses: impl Iterator<Item = String>) -> Vec<String> {
        addresses.filter(|address| ADVISORY_ADDRESSES.contains(&address.as_str()) || self.fleet.iter().any(|(known, _)| known == address)).collect()
    }

    // ------------------------------------------------------------ below the system: firmware, boot, kernel modules

    /// Something changed below the operating system that an update does not explain. Reported with the next look;
    /// nothing is ever done about it from here, because nothing down there is this agent's to change.
    pub fn hardware_changed(&mut self, found: &[crate::hardware::Change], now: f64) {
        for change in found.iter().take(8) {
            let points = (change.points + self.policy.get(change.signal).copied().unwrap_or(0)).clamp(0, 9);
            let key = self.digest(&format!("hardware:{}:{}", change.signal, change.subject));
            if points < 5 || self.trusted.contains(&key) || self.more.extra.len() >= 32 {
                continue;
            }
            self.more.extra.push(json!({"key": key, "level": level_for(points, 1), "score": points, "name": clean(&change.subject, 80), "path": "", "parent": "", "categories": ["hardware"],
                "signals": [{"id": change.signal, "points": points, "category": "hardware", "evidence": clean(&change.evidence, 200)}], "remotes": [],
                "first_seen": now.trunc() as i64, "observed_at": now.trunc() as i64}));
        }
    }

    /// A keyboard this machine had never seen was plugged in just now. Nothing is said about that alone: people
    /// buy keyboards. A command window that opens in the next seconds is judged with it in mind.
    pub fn keyboard_arrived(&mut self, now: f64) {
        self.more.keyboard_at = now;
    }

    // ------------------------------------------------------------ at the network card: the gateway, and a scan

    /// Something was found on the wire that no program here started. Reported with the next look; what is wrong
    /// is on another machine, so nothing is done about it from here.
    pub fn network_found(&mut self, found: &crate::lan::Found, now: f64) {
        let points = (found.points + self.policy.get(found.signal).copied().unwrap_or(0)).clamp(0, 9);
        let key = self.digest(&format!("network:{}:{}", found.signal, found.address));
        if points < 5 || self.trusted.contains(&key) || self.more.extra.len() >= 32 {
            return;
        }
        self.more.extra.push(json!({"key": key, "level": level_for(points, 1), "score": points, "name": clean(&format!("network neighbour {}", found.address), 80), "path": "", "parent": "",
            "categories": ["network"], "signals": [{"id": found.signal, "points": points, "category": "network", "evidence": clean(&found.evidence, 200)}],
            "remotes": [{"address": clean(&found.address, 60), "port": 0, "names": [], "direction": "in"}], "first_seen": now.trunc() as i64, "observed_at": now.trunc() as i64}));
    }

    // ------------------------------------------------------------ a privilege escalation, seen as it happens

    /// A program that has just started and carries the mark of a privilege escalation: root that no program
    /// granted, or a shell under a system helper that starts none. It may be gone before the next full look, so
    /// it is reported now. It is never held or ended here.
    pub(crate) fn escalation_case(&mut self, snap: &crate::linux::Snap, now: f64) {
        let proc = &snap.proc;
        let view = View { name: proc.name.clone(), path: proc.path.clone(), parent_name: snap.parent.clone(), system: self.sensor.system().to_string(),
            cmdline: Some(snap.cmdline.clone()), jumped: snap.jumped, handed: snap.handed, new_keyboard: self.more.keyboard_at > 0.0 && now - self.more.keyboard_at <= 20.0, ..View::default() };
        let outcome = score_process(&view, now, &self.policy, &self.shapes, &self.system_root);
        let marked = outcome.signals.iter().any(|signal| signal.points > 0 && (signal.id == "privilege_jump" || signal.id == "helper_with_child" || signal.id == "keyboard_injection"));
        if !marked || (outcome.level != "SUSPECT" && outcome.level != "HOSTILE") {
            return;
        }
        let key = self.case_key(proc, &snap.parent);
        if self.trusted.contains(&key) || self.more.extra.len() >= 32 || self.more.escalations.get(&key).is_some_and(|said| now - said < 3600.0) {
            return;
        }
        if self.more.escalations.len() >= 512 {
            self.more.escalations.clear();
        }
        self.more.escalations.insert(key.clone(), now);
        let name = clean(&proc.name, 80);
        self.more.extra.push(json!({"key": key, "level": outcome.level, "score": outcome.score, "name": if name.is_empty() { "unknown program".to_string() } else { name },
            "path": clean(&proc.path, 300), "parent": clean(&snap.parent, 80), "categories": outcome.categories,
            "signals": outcome.signals.iter().take(12).map(|signal| json!({"id": signal.id, "points": signal.points, "category": signal.category, "evidence": signal.evidence})).collect::<Vec<_>>(),
            "remotes": [], "first_seen": now.trunc() as i64, "observed_at": now.trunc() as i64}));
    }

    // ------------------------------------------------------------ startup entries that appear while watching

    /// A startup entry that appeared while this agent was watching and that runs something an intruder would.
    #[cfg(unix)]
    pub(crate) fn startup_cases(&mut self, procs: &[Proc], now: f64) -> Vec<Value> {
        let Some(found) = self.more.startup.as_mut().map(|watch| watch.poll()) else { return Vec::new() };
        let mut cases = Vec::new();
        for item in found {
            if item.kind == "sign-in key" {
                cases.extend(self.key_case(&item, procs, now));
                continue;
            }
            let words = String::from_utf8_lossy(&item.lines.join(&b'\n')).into_owned();
            let mut hits: std::collections::BTreeSet<&str> = risky_commands().iter().filter(|(pattern, _)| pattern.is_match(&words)).map(|(_, label)| *label).collect();
            if crate::score::bare_download(&words) {
                hits.insert("a download from a bare internet address");
            }
            let mut files: Vec<String> = startup_drop().find_iter(&words).map(|found| found.as_str().to_string()).collect::<std::collections::BTreeSet<_>>().into_iter().collect();
            files.truncate(8);
            let weighted = |policy: &HashMap<String, i64>, signal: &str, points: i64| (points + policy.get(signal).copied().unwrap_or(0)).clamp(0, 9);
            let mut signals: Vec<Value> = Vec::new();
            let risky = weighted(&self.policy, "risky_command_line", 3);
            if !hits.is_empty() && risky > 0 {
                signals.push(json!({"id": "risky_command_line", "points": risky, "category": "behaviour", "evidence": clean(&format!("A new {} was added that runs: {}.", item.kind, hits.into_iter().collect::<Vec<_>>().join(", ")), 200)}));
            }
            let temp = weighted(&self.policy, "runs_from_temp", 3);
            if !files.is_empty() && temp > 0 {
                signals.push(json!({"id": "runs_from_temp", "points": temp, "category": "identity", "evidence": clean(&format!("A new {} was added that starts a program kept in a temporary folder.", item.kind), 200)}));
            }
            let borrowed = weighted(&self.policy, "system_name_elsewhere", 3);
            if crate::score::borrowed_name(&item.where_, &words) && borrowed > 0 {
                signals.push(json!({"id": "system_name_elsewhere", "points": borrowed, "category": "identity", "evidence": clean(&format!("A new {} carries Apple's name but starts a program kept in a user's folder.", item.kind), 200)}));
            }
            if signals.is_empty() {
                continue; // an ordinary new entry: installing software adds these all the time
            }
            signals.push(json!({"id": "fresh_file", "points": 2, "category": "identity", "evidence": "This startup entry was added while Sentinel was watching."}));
            let key = self.digest(&format!("startup:{}", item.where_));
            let score: i64 = signals.iter().filter_map(|signal| signal["points"].as_i64()).sum();
            let categories: std::collections::BTreeSet<String> = signals.iter().filter_map(|signal| signal["category"].as_str().map(str::to_string)).collect();
            let level = level_for(score, categories.len());
            if self.trusted.contains(&key) || (level != "SUSPECT" && level != "HOSTILE") {
                continue;
            }
            let name = clean(Path::new(&item.where_).file_name().map(|name| name.to_string_lossy().into_owned()).unwrap_or_default().as_str(), 80);
            let mut case = json!({"key": key, "level": level, "score": score, "name": if name.is_empty() { "startup entry".to_string() } else { name }, "path": clean(&item.where_, 300),
                "parent": "", "categories": categories, "signals": signals, "remotes": [], "first_seen": now.trunc() as i64, "observed_at": now.trunc() as i64,
                "persistence": [{"kind": clean(&item.kind, 40), "where": clean(&item.where_, 200)}]});
            if self.hands.is_some() && self.mode == Mode::Kill {
                let mut steps = self.clean_paths(&key, &files, procs, &[], now, &HashSet::new(), now);
                if let Some(cleaner) = self.cleaner() {
                    steps.extend(cleaner.disable(&key, &item.kind, &item.where_, item.whole, &item.lines, now));
                }
                if !steps.is_empty() {
                    steps.truncate(12);
                    case["cleanup"] = json!(steps);
                }
            }
            cases.push(case);
        }
        cases
    }

    /// A key that lets someone sign in over SSH was added to an account while nobody was signed in over SSH:
    /// the way an intruder who got in through a service makes sure of the way back. With a session open it is
    /// taken for the owner's own work. Reported; the key is never touched, so nobody is locked out by a mistake.
    #[cfg(unix)]
    fn key_case(&mut self, item: &crate::clean::Appeared, procs: &[Proc], now: f64) -> Option<Value> {
        let session = procs.iter().any(|proc| proc.ppid > 1 && (proc.name == "sshd" || proc.name == "sshd-session"));
        let points = (5 + self.policy.get("signin_key_added").copied().unwrap_or(0)).clamp(0, 9);
        let key = self.digest(&format!("startup:{}", item.where_));
        if session || points < 5 || self.trusted.contains(&key) {
            return None;
        }
        let account = Path::new(&item.where_).parent().and_then(Path::parent).and_then(Path::file_name).map(|name| name.to_string_lossy().into_owned()).unwrap_or_default();
        let evidence = clean(&format!("{} new SSH sign-in key(s) were added for the account {account} while nobody was signed in over SSH.", item.lines.len()), 200);
        Some(json!({"key": key, "level": level_for(points, 1), "score": points, "name": "authorized_keys", "path": clean(&item.where_, 300), "parent": "", "categories": ["behaviour"],
            "signals": [{"id": "signin_key_added", "points": points, "category": "behaviour", "evidence": evidence}], "remotes": [],
            "first_seen": now.trunc() as i64, "observed_at": now.trunc() as i64, "persistence": [{"kind": "sign-in key", "where": clean(&item.where_, 200)}]}))
    }

    /// The same on Windows: a Run value, a scheduled task, a service or a startup-folder item that appeared while
    /// this agent was watching and that runs something an intruder would. The places are read every few seconds.
    #[cfg(windows)]
    pub(crate) fn startup_cases(&mut self, _procs: &[Proc], now: f64) -> Vec<Value> {
        if now - self.more.startup_at < 5.0 {
            return Vec::new();
        }
        self.more.startup_at = now;
        let Some(found) = self.more.startup.as_mut().map(|watch| watch.poll()) else { return Vec::new() };
        let mut cases = Vec::new();
        for item in found {
            let hits: std::collections::BTreeSet<&str> = risky_commands().iter().filter(|(pattern, _)| pattern.is_match(&item.text)).map(|(_, label)| *label).collect();
            let (temp, files) = crate::startup_win::dropped(&item.text);
            let weighted = |policy: &HashMap<String, i64>, signal: &str, points: i64| (points + policy.get(signal).copied().unwrap_or(0)).clamp(0, 9);
            let mut signals: Vec<Value> = Vec::new();
            let risky = weighted(&self.policy, "risky_command_line", 3);
            if !hits.is_empty() && risky > 0 {
                signals.push(json!({"id": "risky_command_line", "points": risky, "category": "behaviour", "evidence": clean(&format!("A new {} was added that runs: {}.", item.kind, hits.into_iter().collect::<Vec<_>>().join(", ")), 200)}));
            }
            let in_temp = weighted(&self.policy, "runs_from_temp", 3);
            if temp && in_temp > 0 {
                signals.push(json!({"id": "runs_from_temp", "points": in_temp, "category": "identity", "evidence": clean(&format!("A new {} was added that starts a program kept in a temporary folder.", item.kind), 200)}));
            }
            if signals.is_empty() {
                continue; // an ordinary new entry: installing software adds these all the time
            }
            signals.push(json!({"id": "fresh_file", "points": 2, "category": "identity", "evidence": "This startup entry was added while Sentinel was watching."}));
            let key = self.digest(&format!("startup:{}", item.where_.to_lowercase()));
            let score: i64 = signals.iter().filter_map(|signal| signal["points"].as_i64()).sum();
            let categories: std::collections::BTreeSet<String> = signals.iter().filter_map(|signal| signal["category"].as_str().map(str::to_string)).collect();
            let level = level_for(score, categories.len());
            if self.trusted.contains(&key) || (level != "SUSPECT" && level != "HOSTILE") {
                continue;
            }
            let name = clean(item.where_.rsplit(['\\', '/']).next().unwrap_or(""), 80);
            let mut case = json!({"key": key, "level": level, "score": score, "name": if name.is_empty() { "startup entry".to_string() } else { name }, "path": clean(&item.where_, 300),
                "parent": "", "categories": categories, "signals": signals, "remotes": [], "first_seen": now.trunc() as i64, "observed_at": now.trunc() as i64,
                "persistence": [{"kind": clean(item.kind, 40), "where": clean(&item.where_, 200)}]});
            if let (true, Some(directory)) = (self.hands.is_some() && self.mode == Mode::Kill && self.more.clean_up, self.more.directory.clone()) {
                let cleaner = crate::clean_win::Cleaner::new(&directory);
                let mut steps = cleaner.disable(&key, &item, now);
                steps.extend(cleaner.clean(&key, &files, &[], now));
                if !steps.is_empty() {
                    steps.truncate(12);
                    case["cleanup"] = json!(steps);
                }
            }
            cases.push(case);
        }
        cases
    }

    #[cfg(not(any(unix, windows)))]
    pub(crate) fn startup_cases(&mut self, _procs: &[Proc], _now: f64) -> Vec<Value> {
        Vec::new()
    }

    // ------------------------------------------------------------ failed sign-ins

    /// One case per address that failed to sign in over SSH again and again. Reported, never acted on.
    pub(crate) fn signin_cases(&mut self, now: f64) -> Vec<Value> {
        let mut cases = Vec::new();
        for burst in self.sensor.sign_ins().into_iter().take(8) {
            let key = self.digest(&format!("signin:{}", burst.address));
            if self.more.signin_said.len() > 1000 {
                self.more.signin_said.clear();
            }
            // A sign-in that succeeded after the failures is said at once, even inside the hour.
            let news = !burst.accepted.is_empty() && self.more.signin_said.insert(key.clone());
            if self.trusted.contains(&key) || cases.len() >= 4 || (!news && self.reported.get(&key).is_some_and(|previous| now - previous.1 < 3600.0)) {
                continue;
            }
            let mut evidence = format!("The address {} made {} failed SSH sign-ins in a few minutes, trying {} account name(s).", burst.address, burst.count, burst.accounts);
            if !burst.accepted.is_empty() {
                evidence.push_str(&format!(" A sign-in from it then succeeded, as {}.", burst.accepted));
            }
            cases.push(json!({"key": key, "level": "SUSPECT", "score": 5, "name": clean(&format!("SSH sign-ins from {}", burst.address), 80), "path": "", "parent": "",
                "categories": ["directory"], "signals": [{"id": "logon_failure_burst", "points": 5, "category": "directory", "evidence": clean(&evidence, 200)}],
                "remotes": [{"address": burst.address, "port": 0, "names": [], "direction": "in"}], "first_seen": now.trunc() as i64, "observed_at": now.trunc() as i64}));
        }
        cases
    }

    // ------------------------------------------------------------ calls back out of an attacked service

    /// The cases of web clients that attacked, by address: a call from a service back to one is said under its case.
    pub(crate) fn remember_web_attacks(&mut self, cases: &[Value], now: f64) {
        for case in cases {
            let first = &case["remotes"][0];
            if let (Some(address), Some("in")) = (first["address"].as_str(), first["direction"].as_str()) {
                if let Some(plain) = net::canonical(address) {
                    self.more.web_attacks.insert(plain, (case.clone(), now));
                }
            }
        }
        self.more.web_attacks.retain(|_, (_, at)| now - *at <= 3600.0);
    }

    /// Code that runs inside a network-facing service starts no program, so there is nothing to end. What it
    /// still needs is a way back to whoever sent it. A service that a stopped shell came through minutes ago, and
    /// that now opens a connection out to an address that has just connected in to it, is calling its attacker
    /// back; so is a service that connects out to a web client with an open attack case. That one address is
    /// refused at the firewall for an hour (kill and decide modes), and said under the attack's own case.
    pub(crate) fn callback_cases(&mut self, now: f64, cases: &mut Vec<Value>) {
        let sieges = &self.sieges;
        self.more.attacks.retain(|pid, _| sieges.get(pid).is_some_and(|until| *until > now));
        let (before, trusted) = (self.more.callouts.len(), &self.trusted);
        self.more.callouts.retain(|_, (until, key, _)| *until > now && !trusted.contains(key));
        let lifted = self.more.callouts.len() != before;
        let mut found: Vec<(String, u32, String, Value)> = Vec::new();
        if self.sensor.system() != "windows" && !(self.more.attacks.is_empty() && self.more.web_attacks.is_empty()) {
            let serves = |tracked: &super::Tracked| {
                let name = tracked.proc.name.to_lowercase();
                (self.listeners.contains(&tracked.proc.pid) || super::starts(&name, WEB_SERVER_PREFIXES)) && !super::starts(&name, super::LISTENER_EXEMPT)
            };
            for tracked in self.tracked.iter().filter(|tracked| serves(tracked)) {
                let name = tracked.proc.name.to_lowercase();
                for ((address, port), stamps) in &tracked.contacts {
                    if !net::is_internet(address) || !stamps.last().is_some_and(|stamp| now - stamp <= 120.0) {
                        continue;
                    }
                    if self.more.callouts.contains_key(address) || self.more.never_block.contains(address) || self.more.addresses.contains_key(address) || found.iter().any(|(known, ..)| known == address) {
                        continue;
                    }
                    // A server with many workers: the shell came through one, the call may leave from another.
                    let came_in = self.tracked.iter().filter(|other| other.proc.name.to_lowercase() == name)
                        .any(|other| other.inbound.iter().any(|(_, sources)| sources.iter().any(|(source, seen)| source == address && now - seen <= super::SIEGE_SECONDS)));
                    let through = self.more.attacks.iter().find(|(pid, (_, _, service))| **pid == tracked.proc.pid || *service == name).filter(|_| came_in).map(|(_, (case, _, _))| case);
                    let web = self.more.web_attacks.get(address).map(|(case, _)| case);
                    if let Some(case) = through.or(web) {
                        found.push((address.clone(), *port, tracked.proc.name.clone(), case.clone()));
                    }
                }
            }
        }
        let acts = self.hands.is_some() && (self.mode == Mode::Kill || self.mode == Mode::Decide);
        let mut applied = false;
        for (address, port, service, mut case) in found.into_iter().take(4) {
            let key = case["key"].as_str().unwrap_or("").to_string();
            if !is_key(&key) || self.trusted.contains(&key) {
                continue;
            }
            self.more.callouts.insert(address.clone(), (now + 3600.0, key.clone(), acts));
            let refused = acts && self.apply_block();
            applied = applied || acts;
            if acts && !refused {
                if let Some(entry) = self.more.callouts.get_mut(&address) {
                    entry.2 = false; // no firewall tool, or it refused: said as left for a person
                }
            }
            let step = json!({"action": if refused { "disabled" } else { "left" }, "kind": clean(&format!("call out of {service}"), 40), "where": clean(&format!("{address} port {port}"), 200)});
            let remote = json!({"address": clean(&address, 60), "port": port, "names": [], "direction": "out"});
            let add = |case: &mut Value| {
                let mut steps = case["cleanup"].as_array().cloned().unwrap_or_default();
                steps.push(step.clone());
                steps.truncate(12);
                case["cleanup"] = json!(steps);
                let mut remotes = case["remotes"].as_array().cloned().unwrap_or_default();
                if remotes.len() < 8 && !remotes.iter().any(|known| known["address"] == remote["address"] && known["direction"] == "out") {
                    remotes.push(remote.clone());
                    case["remotes"] = json!(remotes);
                }
            };
            match cases.iter_mut().find(|known| known["key"] == key.as_str()) {
                Some(known) => add(known),
                None => {
                    case["observed_at"] = json!(now.trunc() as i64);
                    add(&mut case);
                    cases.push(case);
                }
            }
        }
        if lifted && !applied {
            self.apply_block();
        }
    }

    /// A startup place changed this instant: judge it now. The cases are reported with the next look.
    pub fn startup_changed(&mut self, now: f64) -> bool {
        let procs = self.sensor.running_now();
        let found = self.startup_cases(&procs, now);
        let any = !found.is_empty();
        self.more.extra.extend(found);
        self.urgent = self.urgent || any;
        any
    }

    /// The folders startup entries live in, for whoever watches them for changes.
    pub fn startup_folders(&self) -> Vec<PathBuf> {
        #[cfg(unix)]
        {
            self.more.startup.as_ref().map(|watch| watch.folders()).unwrap_or_default()
        }
        #[cfg(not(unix))]
        {
            Vec::new()
        }
    }

    // ------------------------------------------------------------ what the service tells this agent

    pub fn set_trusted(&mut self, keys: &Value) {
        self.trusted = keys.as_array().map(|list| list.iter().filter_map(Value::as_str).filter(|key| is_key(key)).map(str::to_string).collect()).unwrap_or_default();
    }

    /// {signal id: whole points between -2 and 2}. Anything else from the service is ignored.
    pub fn set_policy(&mut self, value: &Value) {
        self.policy = value.as_object().map(|map| map.iter().filter_map(|(key, item)| {
            let points = item.as_i64().filter(|_| item.is_i64() || item.is_u64())?;
            (signal_name(key) && (-2..=2).contains(&points) && points != 0).then(|| (key.clone(), points))
        }).collect()).unwrap_or_default();
    }

    /// [[signal id, signal id], ...]: pairs the service learned from confirmed attacks.
    pub fn set_shapes(&mut self, value: &Value) {
        let mut shapes: std::collections::BTreeSet<(String, String)> = std::collections::BTreeSet::new();
        for pair in value.as_array().map(|list| list.iter().take(40)).into_iter().flatten() {
            let Some(items) = pair.as_array().filter(|items| items.len() == 2) else { continue };
            let (Some(first), Some(second)) = (items[0].as_str(), items[1].as_str()) else { continue };
            if signal_name(first) && signal_name(second) && first != second {
                shapes.insert(if first <= second { (first.to_string(), second.to_string()) } else { (second.to_string(), first.to_string()) });
            }
        }
        self.shapes = shapes.into_iter().collect();
    }

    /// {address: host} from the service: addresses that currently answer for the watched hosts.
    pub fn set_watch(&mut self, value: &Value) {
        let mut watch = HashMap::new();
        for (address, host) in value.as_object().into_iter().flatten() {
            let Some(host) = host.as_str() else { continue };
            let fine = (3..=120).contains(&host.len()) && host.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'.' || byte == b'-');
            if let (true, true, Some(plain)) = (fine, watch.len() < 600, net::canonical(address)) {
                watch.insert(plain, host.to_string());
            }
        }
        self.more.watch = watch;
    }

    /// {"revision", "addresses"} from the service: the Tor Project's current list of exit nodes.
    pub fn set_exits(&mut self, value: &Value) {
        let (Some(list), Some(revision)) = (value["addresses"].as_array(), value["revision"].as_str()) else { return };
        let exits: HashSet<String> = list.iter().take(6000).filter_map(|item| item.as_str().and_then(net::canonical)).collect();
        self.exits = exits.into_iter().collect();
        self.more.exits_revision = revision.chars().take(64).collect();
    }

    pub fn exits_revision(&self) -> &str {
        &self.more.exits_revision
    }

    /// What the organisation's other machines have learned: {"indicators": {address: why}, "suspects": [addresses]}.
    pub fn set_fleet(&mut self, value: &Value) {
        if !value.is_object() {
            return;
        }
        let mut fleet: Vec<(String, String)> = Vec::new();
        for (address, why) in value["indicators"].as_object().into_iter().flatten() {
            if let (Some(why), Some(plain), true) = (why.as_str(), net::canonical(address), fleet.len() < 400) {
                match fleet.iter_mut().find(|(known, _)| *known == plain) {
                    Some(entry) => entry.1 = clean(why, 120),
                    None => fleet.push((plain, clean(why, 120))),
                }
            }
        }
        let suspects: HashSet<String> = value["suspects"].as_array().map(|list| list.iter().take(200).filter_map(|item| item.as_str().and_then(net::canonical)).collect()).unwrap_or_default();
        self.fleet = fleet;
        self.suspects = suspects.into_iter().filter(|address| !self.more.addresses.contains_key(address)).collect();
        if let Some(wanted) = value.get("block") {
            self.block(wanted);
        }
    }

    /// With the service's fleet blocking on, refuse the internet addresses confirmed attacks were run from. Only a
    /// machine allowed to end programs does this, only for public addresses in the shared list, never for its own
    /// addresses or the service's, and never more than 200.
    fn block(&mut self, wanted: &Value) {
        if self.hands.is_none() || !(self.mode == Mode::Kill || self.mode == Mode::Decide) {
            return;
        }
        let mut target: Vec<String> = wanted.as_array().map(|list| list.iter().filter_map(Value::as_str).filter(|address| {
            self.fleet.iter().any(|(known, _)| known == address) && net::is_internet(address) && !self.more.never_block.contains(*address) && !self.more.addresses.contains_key(*address)
        }).map(str::to_string).collect()).unwrap_or_default();
        target.sort();
        target.dedup();
        target.truncate(200);
        self.more.fleet_block = target;
        self.apply_block();
    }

    /// Refuse exactly the fleet's list and the addresses attacked services called back. True when the firewall
    /// now holds that list.
    /// Everything that should be refused now. Attack addresses are refused only by an agent allowed to end
    /// programs; the privacy shield's by any agent that may act at all.
    fn block_target(&self) -> Vec<String> {
        let acting = self.mode == Mode::Kill || self.mode == Mode::Decide;
        let mut target: Vec<String> = if acting { self.more.callouts.iter().filter(|(_, entry)| entry.2).map(|(address, _)| address.clone()).chain(self.more.fleet_block.iter().cloned()).collect() } else { Vec::new() };
        target.extend(self.more.shield_block.iter().cloned());
        target.truncate(200);
        target.sort();
        target.dedup();
        target
    }

    /// Refuse exactly the fleet's list, the addresses attacked services called back and the privacy shield's.
    /// True when the firewall now holds that list. This writes the firewall while the watcher is held, so it is
    /// only for what cannot wait (an attacked service calling back); the shield's changes go through
    /// `block_wanted` and `block_done`, which let the caller do the writing without holding the watcher.
    fn apply_block(&mut self) -> bool {
        if self.hands.is_none() {
            return false;
        }
        let target = self.block_target();
        if self.more.blocked.as_ref() == Some(&target) {
            return true;
        }
        let Some(done) = self.hands.as_mut().and_then(|hands| hands.block(&target)) else { return false };
        // Nothing to refuse and no firewall tool is not a failure worth reporting.
        self.more.block_failed = !target.is_empty() && !done;
        if done || target.is_empty() {
            self.more.blocked = Some(target);
        }
        done
    }

    /// The list the firewall should hold, when that is not what it holds now: for the caller to write, without
    /// holding the watcher, and then report with `block_done`. `None` when there is nothing to change.
    pub fn block_wanted(&self) -> Option<Vec<String>> {
        self.hands.as_ref()?;
        let target = self.block_target();
        let held = self.more.blocked.as_deref().unwrap_or(&[]);
        (target.as_slice() != held).then_some(target)
    }

    /// The firewall was asked to hold this list. `done` is what the hands answered.
    pub fn block_done(&mut self, target: Vec<String>, done: Option<bool>) {
        let Some(done) = done else { return };
        self.more.block_failed = !target.is_empty() && !done;
        if done || target.is_empty() {
            self.more.blocked = Some(target);
        }
    }

    /// The tracker addresses the privacy shield wants refused now, replacing the ones before. Never this
    /// machine's own addresses, its service's, or anything that is not on the open internet.
    pub fn set_shield(&mut self, addresses: &[String]) {
        let mut wanted: Vec<String> = addresses.iter().filter(|address| net::is_internet(address) && !self.more.never_block.contains(*address) && !self.more.addresses.contains_key(*address)).cloned().collect();
        wanted.sort();
        wanted.dedup();
        // Only noted here. The firewall is written by whoever holds no lock a responder is waiting for.
        self.more.shield_block = wanted;
    }

    /// Remove every address this agent refused. Called when the agent is told to stop.
    pub fn unblock(&mut self) {
        if self.more.blocked.as_ref().is_some_and(|list| !list.is_empty()) && self.hands.as_mut().and_then(|hands| hands.block(&[])) == Some(true) {
            self.more.blocked = Some(Vec::new());
        }
    }

    /// What this machine tells the service about its place in the network and about its own sight.
    pub fn mesh(&mut self, now: f64, privileged: bool) -> Value {
        self.more.addresses.retain(|_, seen| now - *seen <= 3600.0);
        self.more.peers.retain(|_, seen| now - *seen <= 3600.0);
        let mut addresses: Vec<&String> = self.more.addresses.keys().collect();
        addresses.sort();
        addresses.truncate(8);
        let mut peers: Vec<(&(String, u32, &'static str), &f64)> = self.more.peers.iter().collect();
        peers.sort_by(|a, b| b.1.partial_cmp(a.1).unwrap_or(std::cmp::Ordering::Equal).then_with(|| a.0.cmp(b.0)));
        let responds = match (self.hands.is_some(), self.mode) {
            (false, _) => "report",
            (true, Mode::Kill) => "kill",
            (true, Mode::Decide) => "decide",
            (true, Mode::Pause) => "pause",
        };
        json!({"addresses": addresses,
            "peers": peers.into_iter().take(60).map(|((address, port, direction), _)| json!({"address": address, "port": port, "direction": direction})).collect::<Vec<_>>(),
            "coverage": {"privileged": privileged, "process_feed": self.more.process_feed, "host_names": !self.names.is_empty() || !self.more.watch.is_empty(),
                "web_logs": self.more.web.as_ref().map(|web| web.logs.len()).unwrap_or(0), "web_folders": self.more.web.as_ref().map(|web| web.roots.len()).unwrap_or(0), "directory_log": privileged && self.sensor.system() == "windows",
                "responds": responds, "blocking": self.more.blocked.as_ref().map(Vec::len).unwrap_or(0), "block_failed": self.more.block_failed}})
    }

    pub fn status(&self) -> Value {
        json!({"ticks": self.ticks, "processes": self.more.seen.0, "connections": self.more.seen.1, "tracked": self.tracked.len()})
    }

    /// Follow a program a feed reported, outside a full look.
    pub fn note_start(&mut self, snap: &Snap, now: f64) {
        if self.interesting(&snap.proc, &snap.parent) {
            self.follow(&snap.proc, &snap.parent, Some(snap.cmdline.clone()), now);
        }
    }
}
