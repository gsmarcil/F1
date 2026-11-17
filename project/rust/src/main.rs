//! The `garrett` command.
//!
//!   garrett [--state-dir <folder>] run [--mode report|pause|decide|kill] [--clean on|off] [--update on|off]
//!   garrett update [--check]
//!   garrett confirm <case> | learned [--reset]
//!   garrett shield [on|off|allow <name>|cut <name>] | traffic
//!   garrett [--state-dir <folder>] enroll --server <address> --key <key> [--label <name>] [--mode ...] [--patient]
//!   garrett [--state-dir <folder>] cases | trust <case> | stop <case> | release <case> | restore <case>
//!   garrett [--state-dir <folder>] status | forget
//!   garrett version
//!
//! For looking inside: `score` (one program described as JSON on standard input), `processes [folder]`,
//! `watch-starts <seconds>` and `watch-files <seconds>` (Linux, root).

use garrett::score::{containment_reason, score_process, Detection, Remote, View};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::Read;

fn text(value: &Value) -> String {
    value.as_str().unwrap_or("").to_string()
}

/// Build a view from the JSON form the fixtures use.
pub fn view_from(value: &Value) -> View {
    let list = |key: &str| value[key].as_array().cloned().unwrap_or_default();
    View {
        name: text(&value["name"]),
        path: text(&value["path"]),
        parent_name: text(&value["parent_name"]),
        system: text(&value["system"]),
        cmdline: value["cmdline"].as_str().map(str::to_string),
        signature: value["signature"].as_array().map(|pair| (text(&pair[0]), text(&pair[1]))),
        remotes: list("remotes").iter().map(|item| Remote { address: text(&item[0]), port: item[1].as_u64().unwrap_or(0) as u16, names: item[2].as_array().map(|names| names.iter().map(text).collect()).unwrap_or_default() }).collect(),
        contacts: list("contacts").iter().map(|item| (text(&item[0]), item[1].as_u64().unwrap_or(0) as u16, item[2].as_array().map(|times| times.iter().filter_map(Value::as_f64).collect()).unwrap_or_default())).collect(),
        inbound: list("inbound").iter().map(|item| (item[0].as_u64().unwrap_or(0) as u16, item[1].as_array().map(|sources| sources.iter().map(|source| (text(&source[0]), source[1].as_f64().unwrap_or(0.0))).collect()).unwrap_or_default())).collect(),
        trusted: value["trusted"].as_bool().unwrap_or(false),
        baseline_days: value["baseline_days"].as_f64().unwrap_or(0.0),
        baseline_overlap: value["baseline_overlap"].as_f64().unwrap_or(0.0),
        detections: list("detections").iter().map(|item| Detection { name: if item["has_name"].as_bool().unwrap_or(false) { Some(text(&item["name"])) } else { None }, executed: item["executed"].as_bool().unwrap_or(false), active: item["active"].as_bool().unwrap_or(false) }).collect(),
        file_age: value["file_age"].as_f64(),
        events: list("events").iter().map(|item| (text(&item["kind"]), item["count"].as_i64().unwrap_or(0))).collect(),
        origin: text(&value["origin"]),
        agent: list("agent").iter().map(|item| (text(&item[0]), item[1].as_array().map(|numbers| numbers.iter().filter_map(Value::as_i64).collect()).unwrap_or_default())).collect(),
        exits: list("exits").iter().map(text).collect(),
        fleet: list("fleet").iter().map(|item| (text(&item[0]), text(&item[1]))).collect(),
        suspects: list("suspects").iter().map(text).collect(),
        served: value["served"].as_bool().unwrap_or(false),
        siege: value["siege"].as_bool().unwrap_or(false),
        jumped: value["jumped"].as_bool().unwrap_or(false),
        handed: value["handed"].as_bool().unwrap_or(false),
        new_keyboard: value["new_keyboard"].as_bool().unwrap_or(false),
    }
}

fn main() {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    // A command whose reader has stopped reading (`garrett cases | head`) ends quietly, as other commands do.
    // The running agent is left as it is: a closed log must never end it.
    #[cfg(unix)]
    if !arguments.iter().any(|argument| argument == "run") {
        unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) };
    }
    match arguments.first().map(String::as_str) {
        Some("version") => println!("garrett {}", garrett::VERSION),
        Some("score") => {
            let mut raw = String::new();
            std::io::stdin().read_to_string(&mut raw).expect("standard input");
            let input: Value = serde_json::from_str(&raw).expect("a JSON object");
            let policy: HashMap<String, i64> = input["policy"].as_object().map(|map| map.iter().filter_map(|(key, value)| value.as_i64().map(|points| (key.clone(), points))).collect()).unwrap_or_default();
            let shapes: Vec<(String, String)> = input["shapes"].as_array().map(|pairs| pairs.iter().map(|pair| (text(&pair[0]), text(&pair[1]))).collect()).unwrap_or_default();
            let outcome = score_process(&view_from(&input["view"]), input["now"].as_f64().unwrap_or(0.0), &policy, &shapes, input["system_root"].as_str().unwrap_or("c:\\windows\\"));
            let signals: Vec<Value> = outcome.signals.iter().map(|signal| json!({"id": signal.id, "points": signal.points, "category": signal.category, "evidence": signal.evidence})).collect();
            println!("{}", json!({"score": outcome.score, "level": outcome.level, "categories": outcome.categories, "signals": signals, "contain": containment_reason(&outcome)}));
        }
        Some("processes") => {
            let folder = arguments.get(1).map(String::as_str).unwrap_or("/proc");
            for proc in garrett::linux::LinuxSensor::new(std::path::Path::new(folder)).processes() {
                println!("{}", json!([proc.pid, proc.ppid, proc.name, proc.path, proc.started]));
            }
        }
        #[cfg(target_os = "linux")]
        Some("watch-starts") => {
            let seconds: u64 = arguments.get(1).and_then(|value| value.parse().ok()).unwrap_or(5);
            let feed = match garrett::feed::ExecFeed::open(std::path::Path::new("/proc")) {
                Ok(feed) => feed,
                Err(error) => {
                    eprintln!("the kernel's process-start feed is not available here: {error}");
                    std::process::exit(1);
                }
            };
            println!("{}", json!({"feed": "ready"}));
            let until = std::time::Instant::now() + std::time::Duration::from_secs(seconds);
            while let Some(left) = until.checked_duration_since(std::time::Instant::now()) {
                if let Ok(snap) = feed.starts.recv_timeout(left) {
                    println!("{}", json!({"pid": snap.proc.pid, "ppid": snap.proc.ppid, "name": snap.proc.name, "path": snap.proc.path, "parent": snap.parent, "cmdline": snap.cmdline}));
                }
            }
            let (seen, caught) = feed.counts();
            println!("{}", json!({"reported": seen, "found": caught, "blind": feed.blind()}));
        }
        #[cfg(target_os = "linux")]
        Some("watch-files") => {
            let seconds: u64 = arguments.get(1).and_then(|value| value.parse().ok()).unwrap_or(5);
            let (sender, starts) = std::sync::mpsc::channel();
            if let Err(error) = garrett::notify::exec_notify(std::path::Path::new("/proc"), sender) {
                eprintln!("program-start notices by file are not available here: {error}");
                std::process::exit(1);
            }
            println!("{}", json!({"feed": "ready"}));
            let until = std::time::Instant::now() + std::time::Duration::from_secs(seconds);
            while let Some(left) = until.checked_duration_since(std::time::Instant::now()) {
                if let Ok(snap) = starts.recv_timeout(left) {
                    println!("{}", json!({"pid": snap.proc.pid, "ppid": snap.proc.ppid, "name": snap.proc.name, "path": snap.proc.path, "parent": snap.parent, "cmdline": snap.cmdline}));
                }
            }
        }
        _ => std::process::exit(match command(&arguments) {
            Ok(code) => code,
            Err(why) => {
                eprintln!("garrett: {why}");
                1
            }
        }),
    }
}

const USAGE: &str = "usage: garrett [--state-dir <folder>] <command>

  run [--mode report|pause|decide|kill] [--clean on|off] [--update on|off] [--learn <hours>] [--shield on|off]
                        watch this machine: report to the service if enrolled, otherwise protect it by itself.
                        While it runs it installs newer versions of itself, unless --update off.
                        A fresh install learns the machine for a day (--learn) before it acts on a program
                        that only looks suspicious; what is plainly an attack is stopped from the first second
  update [--check]      install the newest version now; --check only says whether there is one
  enroll --server <address> --key <key> [--label <name>] [--mode ...] [--patient]
                        join a Sentinel service
  cases                 without a service: list the latest cases on this machine
  trust <case>          without a service: this program is mine, leave it alone
  stop <case>           without a service: end a program the agent paused
  release <case>        without a service: let a program the agent paused continue
  restore <case>        put back everything cleaned up under a case
  confirm <case>        this was an attack: never leave that program running again
  learned [--reset]     what this machine has learned from your verdicts; --reset forgets it
  hardware              what this machine says about its firmware, boot chain and kernel, and what changed
  shield                the privacy shield: what it refuses, what it leaves open and why
  shield on|off         switch it on or off on this machine (it is on unless you say otherwise)
  shield allow <name>   never refuse this tracker;  shield cut <name>: refuse it although a program here uses it
  traffic               which programs on this machine talk to which trackers
  status                show whether this machine is enrolled
  forget                remove this machine's credential
  version";

/// The value after `--name`, or inside `--name=value`. `Err` when the name is given without a value.
fn option(arguments: &[String], name: &str) -> Result<Option<String>, String> {
    for (index, argument) in arguments.iter().enumerate() {
        if argument == name {
            return arguments.get(index + 1).cloned().map(Some).ok_or(format!("{name} needs a value."));
        }
        if let Some(value) = argument.strip_prefix(&format!("{name}=")) {
            return Ok(Some(value.to_string()));
        }
    }
    Ok(None)
}

fn mode(arguments: &[String]) -> Result<String, String> {
    let wanted = option(arguments, "--mode")?.or_else(|| std::env::var("SENTINEL_MODE").ok().filter(|value| !value.is_empty())).unwrap_or_else(|| "kill".into());
    if !garrett::agent::MODES.contains(&wanted.as_str()) {
        return Err("--mode is one of: report, pause, decide, kill.".into());
    }
    Ok(wanted)
}

fn command(arguments: &[String]) -> Result<i32, String> {
    use garrett::agent::{self, State};
    let mut arguments = arguments.to_vec();
    let mut directory = None;
    if arguments.first().is_some_and(|first| first == "--state-dir" || first.starts_with("--state-dir=")) {
        directory = option(&arguments, "--state-dir")?;
        arguments.drain(..if arguments[0] == "--state-dir" { 2 } else { 1 });
    }
    let state = State::new(directory.as_deref());
    let Some(name) = arguments.first().cloned() else {
        eprintln!("{USAGE}");
        return Ok(2);
    };
    let rest = &arguments[1..];
    let case = || rest.first().cloned().ok_or(format!("Give the case id: garrett {name} <case>"));
    match name.as_str() {
        "enroll" => {
            let server = option(rest, "--server")?.ok_or("Give --server.")?;
            let key = option(rest, "--key")?.or_else(|| std::env::var("SENTINEL_ENROLL_KEY").ok().filter(|value| !value.is_empty())).ok_or("Give --key or set SENTINEL_ENROLL_KEY.")?;
            let wanted = mode(rest)?;
            let saved = agent::enroll(&state, &server, &key, &wanted, option(rest, "--label")?.as_deref(), rest.iter().any(|argument| argument == "--patient"))?;
            let given = saved["mode"].as_str().unwrap_or("report");
            println!("Enrolled with {}. Mode: {given}{}.", saved["server"].as_str().unwrap_or(""), if given != wanted { " (the service allows no more than this)" } else { "" });
            Ok(0)
        }
        "status" => {
            match state.load()? {
                Some(saved) => println!("Enrolled with {}. Mode: {}.", saved["server"].as_str().unwrap_or(""), saved["mode"].as_str().unwrap_or("report")),
                None => println!("Not enrolled with a service: this machine is protected by itself when garrett runs."),
            }
            Ok(0)
        }
        "cases" => {
            for line in agent::local_cases(&state, 30) {
                let words = |key: &str, between: &str| line[key].as_array().map(|list| list.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(between)).unwrap_or_default();
                let acted = words("actions", ",");
                let held = match line["held"].as_str() { Some("learning") => "flagged, left running while learning", Some(why) if !why.is_empty() => "flagged, left running for you to judge", _ => "flagged" };
                println!("{}  {}  {:<8} {}  [{}]  {}", agent::stamp(line["at"].as_i64().unwrap_or(0)), text(&line["key"]), text(&line["level"]), text(&line["name"]), if acted.is_empty() { held } else { &acted }, words("signals", ", "));
            }
            Ok(0)
        }
        "trust" | "stop" | "release" => {
            let key = case()?;
            agent::local_decision(&state, &key, &name)?;
            println!("Noted. The agent applies it within a few seconds.");
            judged(&state, &key, name != "stop", &name);
            Ok(0)
        }
        "confirm" => {
            let key = case()?;
            agent::confirm(&state, &key)?;
            println!("Noted: that was an attack. If the program runs again, the agent will not leave it alone.");
            judged(&state, &key, false, "confirm");
            Ok(0)
        }
        "traffic" => {
            let kept = garrett::shield::recorded(&state.directory);
            let rows = kept["traffic"].as_array().cloned().unwrap_or_default();
            if rows.is_empty() {
                println!("No program on this machine has been seen talking to a tracker yet.");
                return Ok(0);
            }
            println!("{:<28} {:<34} {:>6}  last seen", "program", "tracker", "looks");
            for row in &rows {
                let name = text(&row["tracker"]);
                println!("{:<28} {:<34} {:>6}  {}{}", text(&row["program"]).chars().take(28).collect::<String>(), name, row["looks"].as_u64().unwrap_or(0), agent::stamp(row["last"].as_i64().unwrap_or(0)),
                    if garrett::shield::has_own_network(&name) { "" } else { "  (shared address: may be other traffic to the same company)" });
            }
            Ok(0)
        }
        "shield" => {
            use garrett::shield;
            match rest.first().map(String::as_str) {
                Some("on") | Some("off") => {
                    let on = rest[0] == "on";
                    shield::set_enabled(&state.directory, on).map_err(|error| error.to_string())?;
                    println!("{}", if on { "The privacy shield is on. The agent applies it within a few seconds." } else { "The privacy shield is off. The agent lets everything through again within a few seconds." });
                    return Ok(0);
                }
                Some("allow") | Some("cut") => {
                    let allow = rest[0] == "allow";
                    let name = shield::choose(&state.directory, rest.get(1).ok_or("Give the tracker's name: garrett shield allow <name>")?, allow)?;
                    println!("{}", if allow { format!("{name} will never be refused on this machine.") } else { format!("{name} will be refused on this machine, whatever uses it.") });
                    if !allow && !shield::has_own_network(&name) {
                        println!("Its addresses are shared with other sites, so the firewall cannot refuse it without breaking them: it stays measured only.");
                    }
                    return Ok(0);
                }
                Some(_) => return Err("garrett shield, or: garrett shield on|off|allow <name>|cut <name>".into()),
                None => {}
            }
            let kept = shield::recorded(&state.directory);
            if !shield::enabled(&state.directory, true) {
                println!("The privacy shield is off on this machine. Switch it on with: garrett shield on");
                return Ok(0);
            }
            let left = kept["measure_until"].as_f64().unwrap_or(0.0) - agent::now();
            let cut: Vec<String> = kept["cut"].as_array().into_iter().flatten().map(text).collect();
            let (allowed, forced) = shield::choices(&state.directory);
            // A company's names are judged together.
            let mut used: std::collections::BTreeMap<&str, std::collections::BTreeSet<String>> = std::collections::BTreeMap::new();
            for row in kept["traffic"].as_array().into_iter().flatten().filter(|row| row["browser"] != true) {
                if let Some(who) = shield::company(&text(&row["tracker"])) {
                    used.entry(who).or_default().insert(text(&row["program"]));
                }
            }
            let of = |names: &[String]| -> Vec<&str> { names.iter().filter_map(|name| shield::company(name)).collect() };
            let (allowed, forced) = (of(&allowed), of(&forced));
            println!("The privacy shield is on.");
            if kept.get("measure_until").is_none() {
                println!("It has not run yet: the agent starts it.");
            } else if left > 0.0 {
                println!("Measuring for about {:.0} more hour(s) before it refuses anything: garrett traffic", (left / 3600.0).ceil());
            }
            println!("Refused at the firewall now: {}", if cut.is_empty() { "nothing".to_string() } else { cut.join(", ") });
            for name in shield::TRACKERS.iter().filter(|name| shield::has_own_network(name) && !cut.contains(&name.to_string())) {
                let Some(who) = shield::company(name) else { continue };
                if allowed.contains(&who) {
                    println!("  left open, you allowed it: {name}");
                } else if let Some(programs) = used.get(who).filter(|_| !forced.contains(&who)) {
                    println!("  left open, your software uses it ({}): {name}", programs.iter().cloned().collect::<Vec<_>>().join(", "));
                }
            }
            let shared = shield::TRACKERS.iter().filter(|name| !shield::has_own_network(name)).count();
            println!("Measured but never refused: {shared} tracker names whose addresses are shared with sites people visit. Refusing those addresses would break the sites.");
            Ok(0)
        }
        "hardware" => {
            let facts = garrett::hardware::read(true);
            println!("Below the system, as this machine tells it now:");
            for line in garrett::hardware::describe(&facts) {
                println!("{line}");
            }
            match garrett::lan::read() {
                Some(seen) if seen.table.contains_key(&seen.gateway) => println!("  network gateway     its hardware address is kept, with {} neighbour(s) on the network", seen.table.len().saturating_sub(1)),
                Some(_) => println!("  network gateway     has not answered yet"),
                None => println!("  network gateway     could not be read here"),
            }
            let kept = garrett::hardware::HardwareWatch::new(&state.directory);
            match kept.known() {
                Some(before) => {
                    let updated = before.get("loader_update_seen").and_then(|seen| seen.parse::<f64>().ok()).unwrap_or(0.0);
                    let found = garrett::hardware::changes(before, &facts, updated, agent::now());
                    if found.is_empty() {
                        println!("Nothing has changed since the agent's last reading that an update does not explain.");
                    }
                    for change in found {
                        println!("CHANGED  {}", change.evidence);
                    }
                }
                None => println!("The running agent has not kept a reading yet (it does within seconds of starting)."),
            }
            println!("garrett reads these and never writes to them. A change is reported as a case; it is yours to judge.");
            Ok(0)
        }
        "learned" => {
            if rest.iter().any(|argument| argument == "--reset") {
                garrett::learn::forget(&state.directory);
                println!("Everything learned from your verdicts was forgotten.");
                return Ok(0);
            }
            let learned = garrett::learn::learned(&state.directory);
            let settled = std::fs::read(state.directory.join("settled.json")).ok().and_then(|raw| serde_json::from_slice::<Value>(&raw).ok()).unwrap_or(Value::Null);
            let left = settled["until"].as_f64().unwrap_or(0.0) - agent::now();
            let held = settled["held"].as_array().map(Vec::len).unwrap_or(0);
            if left > 0.0 {
                println!("Still learning this machine for about {:.0} more hour(s). Attacks are stopped as always.", (left / 3600.0).ceil());
            } else {
                println!("Settled in: acting on everything it judges hostile.");
            }
            if held > 0 {
                println!("{held} program(s) met while settling in are reported but left running until you judge them: garrett cases");
            }
            println!("Your verdicts: {} mine, {} attack.", learned["verdicts"]["mine"].as_i64().unwrap_or(0), learned["verdicts"]["attack"].as_i64().unwrap_or(0));
            for (id, delta) in learned["policy"].as_object().into_iter().flatten() {
                println!("  {id} counts {} here", match delta.as_i64().unwrap_or(0) { 2 => "two points more", 1 => "one point more", -1 => "one point less", _ => "two points less" });
            }
            for pair in learned["shapes"].as_array().into_iter().flatten() {
                println!("  {} together with {} is a sign of attack here", text(&pair[0]), text(&pair[1]));
            }
            for line in learned["refused"].as_array().into_iter().flatten() {
                println!("  not learned: {}", text(line));
            }
            if state.load()?.is_some() {
                println!("This machine is enrolled: weights and attack signs come from its service.");
            }
            Ok(0)
        }
        "version" => {
            println!("garrett {}", garrett::VERSION);
            Ok(0)
        }
        "restore" => restore(&state, &case()?),
        "forget" => {
            let released = let_go(&state);
            state.remove();
            println!("Credential removed. {}Remove the device on the service as well.", if released > 0 { format!("{released} paused program(s) were let continue, since the service can no longer decide them. ") } else { String::new() });
            Ok(0)
        }
        "run" => {
            let clean = option(rest, "--clean")?.or_else(|| std::env::var("SENTINEL_CLEAN").ok().filter(|value| !value.is_empty())).unwrap_or_else(|| "on".into());
            if clean != "on" && clean != "off" {
                return Err("--clean is on or off.".into());
            }
            let update = option(rest, "--update")?.or_else(|| std::env::var("GARRETT_UPDATE").ok().filter(|value| !value.is_empty())).unwrap_or_else(|| "on".into());
            if update != "on" && update != "off" {
                return Err("--update is on or off.".into());
            }
            let shield = option(rest, "--shield")?.or_else(|| std::env::var("GARRETT_SHIELD").ok().filter(|value| !value.is_empty())).unwrap_or_else(|| "on".into());
            if shield != "on" && shield != "off" {
                return Err("--shield is on or off.".into());
            }
            garrett::run::set_shield(shield == "on");
            let learn = option(rest, "--learn")?.or_else(|| std::env::var("GARRETT_LEARN_HOURS").ok().filter(|value| !value.is_empty())).unwrap_or_else(|| "24".into());
            garrett::run::set_learn_hours(learn.parse::<f64>().ok().filter(|hours| hours.is_finite() && *hours >= 0.0).ok_or("--learn is a number of hours, 0 for none.")?);
            let wanted = mode(rest)?;
            // Where this program file is now: after an update the same place holds the new one.
            let exe = std::env::current_exe().ok();
            if update == "on" {
                garrett::run::keep_current();
            }
            let code = run(&state, &wanted, clean != "off")?;
            if let (true, Some(exe)) = (garrett::run::starting_again(), exe) {
                garrett::update::start_again(&exe);
            }
            Ok(code)
        }
        "update" => {
            use garrett::update::{self, Outcome};
            let base = update::source();
            if rest.iter().any(|argument| argument == "--check") {
                match update::check(&base)? {
                    Some(listed) => println!("garrett {} is out. This is {}. Install it with: garrett update", listed.version, garrett::VERSION),
                    None => println!("garrett {} is the newest version.", garrett::VERSION),
                }
                return Ok(0);
            }
            match update::bring_current(&base)? {
                Outcome::Current => {
                    println!("garrett {} is the newest version.", garrett::VERSION);
                    Ok(0)
                }
                Outcome::Packaged(version) => {
                    println!("garrett {version} is out. apt is installing it and restarts the agent by itself.");
                    Ok(0)
                }
                // 10 tells the launcher that the program file changed, so it restarts the service.
                Outcome::Replaced(version) => {
                    println!("garrett {version} is installed (this was {}).", garrett::VERSION);
                    #[cfg(windows)]
                    if update::as_task() {
                        let quiet = |arguments: &[&str]| std::process::Command::new("schtasks.exe").args(arguments).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).status().is_ok_and(|status| status.success());
                        quiet(&["/End", "/TN", "garrett"]);
                        std::thread::sleep(std::time::Duration::from_secs(2));
                        println!("{}", if quiet(&["/Run", "/TN", "garrett"]) { "The agent was started again on the new version." } else { "Start the agent again to run it: schtasks /Run /TN garrett" });
                        return Ok(0);
                    }
                    Ok(10)
                }
            }
        }
        _ => {
            eprintln!("{USAGE}");
            Ok(2)
        }
    }
}

/// The owner judged a case on a machine that keeps its own cases: remember it and say what was learned.
fn judged(state: &garrett::agent::State, key: &str, mine: bool, how: &str) {
    use garrett::agent;
    let Some(case) = agent::local_cases(state, 5000).into_iter().rev().find(|line| line["key"] == key) else { return };
    if let Ok(said) = garrett::learn::remember(&state.directory, &case, mine, how, agent::now()) {
        for line in said {
            println!("Learned: {line}.");
        }
    }
}

fn restore(state: &garrett::agent::State, key: &str) -> Result<i32, String> {
    use garrett::agent;
    #[cfg(unix)]
    let (back, left) = garrett::clean::Cleaner::new(agent::platform().ok_or("This platform is not supported.")?, &state.directory, None, false).restore(key, agent::now());
    #[cfg(windows)]
    let (back, left) = garrett::clean_win::Cleaner::new(&state.directory).restore(key, agent::now());
    let enrolled = state.load()?.is_some();
    if !enrolled && back > 0 {
        agent::local_decision(state, key, "trust")?; // put back on purpose: the agent leaves this program alone from now on
        judged(state, key, true, "restore");
    }
    println!("{back} thing(s) put back.{}{}{}",
        if left > 0 { format!(" {left} could not be put back; run this again as root or an administrator.") } else { String::new() },
        if back == 0 && left == 0 { " Nothing was cleaned up under that case." } else { "" },
        if back > 0 && enrolled { " If this machine reports to a service, mark the case as yours there too, or the agent may stop the program again." } else { "" });
    Ok(if left > 0 { 1 } else { 0 })
}

fn let_go(state: &garrett::agent::State) -> usize {
    garrett::run::let_go(state)
}

fn run(state: &garrett::agent::State, mode: &str, clean: bool) -> Result<i32, String> {
    match state.load()? {
        Some(saved) => Ok(garrett::run::run(state, &saved, clean)),
        None => Ok(garrett::run::run_alone(state, mode, clean)),
    }
}
