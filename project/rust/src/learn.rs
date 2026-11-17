//! What a machine with no service learns from its owner.
//!
//! Every time the owner judges a case (`garrett trust`, `restore`, `release`: this is mine; `garrett stop`,
//! `confirm`: this was an attack) the verdict is kept in `verdicts.jsonl`, as the case's SHAPE: its signal ids and
//! the verdict, never a name, a path, an address or a command line. From that history two things are worked out,
//! by the same rules the service uses for a fleet (server/src/learning.mjs):
//!
//! Weights. A signal the owner keeps calling theirs is worth less on this machine; one they keep confirming is
//! worth more. A change is one point per step and two in total, never touches a locked signal, and is taken only
//! if every case the owner confirmed and every reference attack would still be reported with it.
//!
//! Pairs. Two signals that confirmed attacks share, and that nothing marked "mine" ever had, become a signal of
//! their own (`learned_attack_shape`).
//!
//! No model is involved, and everything learned can be listed (`garrett learned`) and forgotten
//! (`garrett learned --reset`). An enrolled machine learns from its service instead.

use crate::score::level_for;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// Every signal the agent raises about a program: (id, base weight, category). The same table as
/// server/src/signals.mjs, which a test compares it with.
pub const SIGNALS: &[(&str, i64, &str)] = &[
    ("unsigned_program", 2, "identity"), ("user_writable_path", 1, "identity"), ("runs_from_temp", 3, "identity"), ("fresh_file", 2, "identity"),
    ("system_name_elsewhere", 3, "identity"), ("advisory_tool_name", 2, "identity"), ("script_from_document", 3, "lineage"),
    ("shell_from_web_server", 3, "lineage"), ("risky_command_line", 3, "lineage"), ("script_from_shortcut", 3, "lineage"),
    ("program_from_attachment", 3, "lineage"), ("remote_session_shell", 3, "lineage"), ("helper_with_child", 5, "lineage"), ("privilege_jump", 6, "privilege"), ("signin_key_added", 5, "behaviour"),
    ("hidden_browser", 5, "behaviour"), ("remote_control_tool", 3, "behaviour"), ("address_lookup_host", 1, "destinations"),
    ("boot_protection_off", 6, "hardware"), ("boot_entry_added", 5, "hardware"), ("firmware_downgraded", 5, "hardware"), ("firmware_changed_unannounced", 6, "hardware"),
    ("kernel_module_loose", 5, "hardware"), ("driver_checks_off", 6, "hardware"), ("boot_code_changed", 6, "hardware"),
    ("gateway_impersonated", 6, "network"), ("port_scan", 5, "network"), ("keyboard_injection", 5, "behaviour"),
    ("system_tool_misuse", 4, "behaviour"),
    ("discovery_command", 2, "behaviour"), ("threat_executed", 3, "behaviour"), ("antivirus_detection", 5, "antivirus"), ("tor_routing", 3, "destinations"),
    ("learned_attack_shape", 2, "learned"), ("fleet_indicator", 3, "destinations"), ("metadata_access_from_web", 2, "behaviour"),
    ("advisory_indicator", 5, "destinations"), ("drop_or_tunnel_host", 2, "destinations"), ("llm_api_host", 1, "destinations"), ("unusual_port", 1, "destinations"),
    ("beaconing", 3, "pattern"), ("fan_out", 2, "pattern"), ("agent_command_stream", 3, "agent"), ("agent_retry_variation", 2, "agent"),
    ("agent_parallel_duplicates", 2, "agent"), ("web_fuzzing", 3, "web"), ("web_injection_attempt", 3, "web"), ("web_injection_answered", 2, "web"),
    ("web_enumeration", 3, "web"), ("web_login_burst", 3, "web"), ("web_shell_request", 3, "web"), ("web_error_burst", 2, "web"), ("web_shell_file", 5, "web"),
    ("inbound_from_suspect_peer", 4, "inbound"), ("inbound_tor_exit", 2, "inbound"), ("inbound_advisory_indicator", 5, "inbound"),
    ("remote_access_burst", 5, "inbound"), ("credential_theft_tool", 6, "directory"), ("directory_recon", 2, "directory"), ("kerberoast_pattern", 5, "directory"),
    ("dcsync_pattern", 7, "directory"), ("logon_failure_burst", 5, "directory"), ("audit_log_cleared", 5, "directory"), ("privileged_group_change", 5, "directory"),
];

/// Never learned up or down: published indicators, the antivirus's own verdict, attacks on a service, and
/// directory attacks.
pub const LOCKED: &[&str] = &["learned_attack_shape", "fleet_indicator", "inbound_from_suspect_peer", "web_shell_file", "advisory_indicator", "inbound_advisory_indicator",
    "antivirus_detection", "threat_executed", "remote_access_burst", "credential_theft_tool", "kerberoast_pattern", "dcsync_pattern", "logon_failure_burst", "audit_log_cleared",
    "privileged_group_change"];

/// Attack shapes that must stay reported whatever this machine learns.
pub const REFERENCE_ATTACKS: &[&[&str]] = &[
    &["shell_from_web_server", "risky_command_line"], &["shell_from_web_server", "discovery_command"], &["shell_from_web_server", "agent_command_stream"],
    &["script_from_document", "risky_command_line"], &["script_from_shortcut", "risky_command_line"],
    &["program_from_attachment", "fresh_file"], &["program_from_attachment", "unsigned_program"],
    &["system_tool_misuse", "unusual_port"], &["runs_from_temp", "unusual_port", "beaconing"], &["runs_from_temp", "fan_out"],
    &["runs_from_temp", "advisory_tool_name"], &["unsigned_program", "user_writable_path", "beaconing"],
    &["remote_session_shell", "directory_recon"], &["remote_session_shell", "risky_command_line"],
    &["fleet_indicator", "runs_from_temp"], &["fleet_indicator", "unsigned_program"], &["inbound_from_suspect_peer", "remote_session_shell"],
    &["web_shell_file"], &["web_fuzzing", "web_injection_attempt"], &["web_injection_attempt", "web_injection_answered"], &["web_login_burst", "web_enumeration"],
    &["advisory_indicator"], &["inbound_advisory_indicator"], &["remote_access_burst"], &["antivirus_detection"], &["credential_theft_tool"],
    &["helper_with_child"], &["privilege_jump"],
    &["kerberoast_pattern"], &["dcsync_pattern"], &["logon_failure_burst"], &["audit_log_cleared"], &["privileged_group_change"],
];

pub const HISTORY_MAX: usize = 500;
pub const SHAPES_MAX: usize = 20;

fn known(id: &str) -> Option<(i64, &'static str)> {
    SIGNALS.iter().find(|(name, _, _)| *name == id).map(|(_, weight, category)| (*weight, *category))
}

/// One judged case: what it looked like, and whether the owner called it theirs.
#[derive(Clone, Debug, PartialEq)]
pub struct Verdict {
    pub key: String,
    pub shape: Vec<String>,
    pub mine: bool,
}

/// A case's shape: its signal ids, sorted, each once. A signal this agent does not know, or the learned one, is
/// left out.
pub fn shape_of<'a>(signals: impl Iterator<Item = &'a str>) -> Vec<String> {
    let found: BTreeSet<&str> = signals.filter(|id| known(id).is_some() && *id != "learned_attack_shape").collect();
    found.into_iter().map(str::to_string).collect()
}

/// (score, level) of a shape under a set of learned weights.
pub fn score_shape<S: AsRef<str>>(shape: &[S], policy: &BTreeMap<String, i64>) -> (i64, &'static str) {
    let (mut score, mut categories) = (0, BTreeSet::new());
    for id in shape {
        let Some((weight, category)) = known(id.as_ref()) else { continue };
        let points = (weight + policy.get(id.as_ref()).copied().unwrap_or(0)).clamp(0, 9);
        if points > 0 {
            score += points;
            categories.insert(category);
        }
    }
    (score, level_for(score, categories.len()))
}

fn reported(level: &str) -> bool {
    level == "SUSPECT" || level == "HOSTILE"
}

/// One step of weight learning from the whole history. Returns (the weights, what changed, what was refused).
pub fn learn_policy(history: &[Verdict], current: &BTreeMap<String, i64>) -> (BTreeMap<String, i64>, Vec<String>, Vec<String>) {
    let (mut mine, mut attack): (BTreeMap<&str, usize>, BTreeMap<&str, usize>) = (BTreeMap::new(), BTreeMap::new());
    for verdict in history {
        for id in &verdict.shape {
            *(if verdict.mine { &mut mine } else { &mut attack }).entry(id.as_str()).or_insert(0) += 1;
        }
    }
    let mut policy: BTreeMap<String, i64> = current.iter().filter(|(id, delta)| known(id).is_some() && !LOCKED.contains(&id.as_str()) && **delta != 0 && delta.abs() <= 2).map(|(id, delta)| (id.clone(), *delta)).collect();
    let must_stay: Vec<Vec<String>> = history.iter().filter(|verdict| !verdict.mine).map(|verdict| verdict.shape.clone())
        .chain(REFERENCE_ATTACKS.iter().map(|shape| shape.iter().map(|id| id.to_string()).collect())).collect();
    let (mut changes, mut refused) = (Vec::new(), Vec::new());
    for (id, _, _) in SIGNALS.iter().filter(|(id, _, _)| !LOCKED.contains(id)) {
        let (d, c, have) = (mine.get(id).copied().unwrap_or(0), attack.get(id).copied().unwrap_or(0), policy.get(*id).copied().unwrap_or(0));
        // Three "mine" and no confirmation move a signal down a point; six move it two. Confirmations mirror it.
        let want = if c == 0 && d >= 6 { -2 } else if c == 0 && d >= 3 { -1 } else if d == 0 && c >= 4 { 2 } else if d == 0 && c >= 2 { 1 } else { 0 };
        if want == have {
            continue;
        }
        let next = have + (want - have).signum();
        let mut candidate = policy.clone();
        if next == 0 {
            candidate.remove(*id);
        } else {
            candidate.insert(id.to_string(), next);
        }
        if let Some(lost) = must_stay.iter().find(|shape| reported(score_shape(shape, &policy).1) && !reported(score_shape(shape, &candidate).1)) {
            refused.push(format!("{id} to {next:+}: {} would no longer be reported", lost.join(" + ")));
            continue;
        }
        policy = candidate;
        changes.push(format!("{id} {have:+} -> {next:+}"));
    }
    (policy, changes, refused)
}

/// Pairs of signals that at least two confirmed attacks share and nothing marked "mine" ever had.
pub fn learn_shapes(history: &[Verdict]) -> Vec<(String, String)> {
    let mut pairs: BTreeMap<(String, String), (usize, usize)> = BTreeMap::new();
    for verdict in history {
        for (index, first) in verdict.shape.iter().enumerate() {
            for second in &verdict.shape[index + 1..] {
                let entry = pairs.entry((first.clone(), second.clone())).or_insert((0, 0));
                if verdict.mine { entry.1 += 1 } else { entry.0 += 1 }
            }
        }
    }
    let mut found: Vec<((String, String), usize)> = pairs.into_iter().filter(|(_, (confirmed, mine))| *mine == 0 && *confirmed >= 2).map(|(pair, (confirmed, _))| (pair, confirmed)).collect();
    found.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    found.into_iter().take(SHAPES_MAX).map(|(pair, _)| pair).collect()
}

fn read_history(directory: &Path) -> Vec<Verdict> {
    let Ok(raw) = std::fs::read_to_string(directory.join("verdicts.jsonl")) else { return Vec::new() };
    let mut found: Vec<Verdict> = Vec::new();
    for line in raw.lines().filter_map(|line| serde_json::from_str::<Value>(line).ok()) {
        let (Some(key), Some(verdict)) = (line["key"].as_str(), line["verdict"].as_str()) else { continue };
        let shape = shape_of(line["shape"].as_array().into_iter().flatten().filter_map(Value::as_str));
        if shape.is_empty() || !matches!(verdict, "mine" | "attack") {
            continue;
        }
        // The owner's latest word on a case is the one that counts.
        found.retain(|known| known.key != key);
        found.push(Verdict { key: key.to_string(), shape, mine: verdict == "mine" });
    }
    let extra = found.len().saturating_sub(HISTORY_MAX);
    found.drain(..extra);
    found
}

fn write_private(path: &Path, body: &str) -> std::io::Result<()> {
    let temporary = path.with_extension("tmp");
    std::fs::write(&temporary, body)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o600));
    }
    std::fs::rename(&temporary, path)
}

/// Keep the owner's verdict on a case and work out again what this machine has learned. `case` is the case's line
/// in cases.jsonl; `how` is the command the owner used. Returns what changed, to be said.
pub fn remember(directory: &Path, case: &Value, mine: bool, how: &str, now: f64) -> std::io::Result<Vec<String>> {
    let Some(key) = case["key"].as_str() else { return Ok(Vec::new()) };
    let shape = shape_of(case["signals"].as_array().into_iter().flatten().filter_map(Value::as_str));
    if shape.is_empty() {
        return Ok(Vec::new());
    }
    std::fs::create_dir_all(directory)?;
    let mut lines: Vec<String> = std::fs::read_to_string(directory.join("verdicts.jsonl")).map(|raw| raw.lines().map(str::to_string).collect()).unwrap_or_default();
    lines.push(json!({"at": now.trunc() as i64, "key": key, "verdict": if mine { "mine" } else { "attack" }, "how": how, "shape": shape}).to_string());
    let extra = lines.len().saturating_sub(HISTORY_MAX * 2);
    lines.drain(..extra);
    write_private(&directory.join("verdicts.jsonl"), &(lines.join("\n") + "\n"))?;
    let history = read_history(directory);
    let before = learned(directory);
    let current: BTreeMap<String, i64> = before["policy"].as_object().map(|map| map.iter().filter_map(|(id, delta)| delta.as_i64().map(|delta| (id.clone(), delta))).collect()).unwrap_or_default();
    let (policy, changes, refused) = learn_policy(&history, &current);
    let shapes = learn_shapes(&history);
    let mut said: Vec<String> = changes.iter().map(|change| format!("weight {change}")).collect();
    let had: BTreeSet<String> = before["shapes"].as_array().into_iter().flatten().map(|pair| pair.to_string()).collect();
    for (first, second) in &shapes {
        if !had.contains(&json!([first, second]).to_string()) {
            said.push(format!("{first} with {second} is now a sign of attack here"));
        }
    }
    let attacks: Vec<&str> = history.iter().filter(|verdict| !verdict.mine).map(|verdict| verdict.key.as_str()).collect();
    write_private(&directory.join("learned.json"), &json!({"at": now.trunc() as i64, "policy": policy, "shapes": shapes.iter().map(|(first, second)| json!([first, second])).collect::<Vec<_>>(),
        "verdicts": {"mine": history.iter().filter(|verdict| verdict.mine).count(), "attack": attacks.len()}, "confirmed": attacks, "refused": refused}).to_string())?;
    Ok(said)
}

/// What this machine has learned so far: `{"policy", "shapes", "verdicts", "confirmed", "refused"}`, or `{}`.
pub fn learned(directory: &Path) -> Value {
    std::fs::read(directory.join("learned.json")).ok().and_then(|raw| serde_json::from_slice::<Value>(&raw).ok()).filter(Value::is_object).unwrap_or_else(|| json!({}))
}

/// Forget every verdict and everything worked out from them.
pub fn forget(directory: &Path) {
    let _ = std::fs::remove_file(directory.join("verdicts.jsonl"));
    let _ = std::fs::remove_file(directory.join("learned.json"));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn verdict(key: &str, shape: &[&str], mine: bool) -> Verdict {
        Verdict { key: key.into(), shape: shape.iter().map(|id| id.to_string()).collect(), mine }
    }

    #[test]
    fn three_times_mine_lowers_a_signal_one_point_and_a_confirmation_stops_that() {
        let mut history: Vec<Verdict> = (0..3).map(|number| verdict(&format!("k{number}"), &["drop_or_tunnel_host", "tor_routing", "unusual_port"], true)).collect();
        let (policy, changes, refused) = learn_policy(&history, &BTreeMap::new());
        assert_eq!(policy.get("drop_or_tunnel_host"), Some(&-1));
        assert_eq!(policy.get("tor_routing"), Some(&-1));
        // A program misusing a system tool on an odd port must stay reported: that weight does not move.
        assert_eq!(policy.get("unusual_port"), None);
        assert_eq!((changes.len(), refused.len()), (2, 1), "{changes:?} {refused:?}");
        // One step at a time, however long the history, and never more than two points.
        history.extend((3..9).map(|number| verdict(&format!("k{number}"), &["drop_or_tunnel_host"], true)));
        let (again, _, _) = learn_policy(&history, &policy);
        assert_eq!(again.get("drop_or_tunnel_host"), Some(&-2));
        let (still, _, _) = learn_policy(&history, &again);
        assert_eq!(still.get("drop_or_tunnel_host"), Some(&-2));
        history.push(verdict("attack", &["drop_or_tunnel_host", "beaconing"], false));
        let (back, _, _) = learn_policy(&history, &still);
        assert_eq!(back.get("drop_or_tunnel_host"), Some(&-1), "a confirmed attack with that signal takes the discount back, a step at a time");
    }

    #[test]
    fn nothing_learned_may_hide_a_confirmed_attack_or_a_reference_attack_or_move_a_locked_signal() {
        // Six harmless cases would take two points off both signals of a reference attack: the second step is refused.
        let mut history: Vec<Verdict> = (0..6).map(|number| verdict(&format!("k{number}"), &["shell_from_web_server", "risky_command_line"], true)).collect();
        let mut policy = BTreeMap::new();
        for _ in 0..4 {
            policy = learn_policy(&history, &policy).0;
        }
        assert!(reported(score_shape(&["shell_from_web_server", "risky_command_line"], &policy).1), "{policy:?}");
        let (_, _, refused) = learn_policy(&history, &policy);
        assert!(!refused.is_empty());
        history = (0..9).map(|number| verdict(&format!("a{number}"), &["advisory_indicator", "credential_theft_tool"], true)).collect();
        assert!(learn_policy(&history, &BTreeMap::new()).0.is_empty(), "locked signals never move");
    }

    #[test]
    fn a_pair_two_confirmed_attacks_share_becomes_a_sign_until_something_of_the_owners_has_it_too() {
        let mut history = vec![verdict("a", &["beaconing", "unsigned_program", "unusual_port"], false), verdict("b", &["beaconing", "unusual_port"], false)];
        assert_eq!(learn_shapes(&history), vec![("beaconing".to_string(), "unusual_port".to_string())]);
        history.push(verdict("c", &["beaconing", "unusual_port"], true));
        assert!(learn_shapes(&history).is_empty());
    }

    #[test]
    fn verdicts_are_kept_as_shapes_and_the_latest_word_on_a_case_counts() {
        let folder = std::env::temp_dir().join(format!("garrett-learn-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&folder);
        let case = |key: &str| json!({"key": key, "name": "updater", "path": "/tmp/x/updater", "signals": ["tor_routing", "drop_or_tunnel_host", "not_a_signal"]});
        for number in 0..3 {
            remember(&folder, &case(&format!("{number:032}")), true, "trust", 100.0).unwrap();
        }
        let kept = std::fs::read_to_string(folder.join("verdicts.jsonl")).unwrap();
        assert!(!kept.contains("updater") && !kept.contains("/tmp") && !kept.contains("not_a_signal"), "{kept}");
        assert_eq!(learned(&folder)["policy"], json!({"drop_or_tunnel_host": -1, "tor_routing": -1}));
        assert_eq!(learned(&folder)["verdicts"], json!({"mine": 3, "attack": 0}));
        // The owner changes their mind about one of them.
        remember(&folder, &case(&format!("{:032}", 0)), false, "confirm", 200.0).unwrap();
        assert_eq!(learned(&folder)["verdicts"], json!({"mine": 2, "attack": 1}));
        assert_eq!(learned(&folder)["confirmed"], json!([format!("{:032}", 0)]));
        forget(&folder);
        assert_eq!(learned(&folder), json!({}));
        let _ = std::fs::remove_dir_all(&folder);
    }

    #[test]
    fn the_signal_table_is_the_services_table() {
        let source = include_str!("../../server/src/signals.mjs");
        let entry = regex::Regex::new(r"(?m)^\s+([a-z_]+): S\((\d+), '([a-z]+)',").unwrap();
        let theirs: BTreeMap<String, (i64, String)> = entry.captures_iter(source).map(|found| (found[1].to_string(), (found[2].parse().unwrap(), found[3].to_string()))).collect();
        assert!(theirs.len() >= 50, "the service's table was not read: {}", theirs.len());
        for (id, weight, category) in SIGNALS {
            assert_eq!(theirs.get(*id), Some(&(*weight, category.to_string())), "{id}");
        }
        for (id, (_, category)) in &theirs {
            assert!(category == "cloud" || known(id).is_some(), "{id} is missing here");
        }
        let locked = regex::Regex::new(r"export const LOCKED = new Set\(\[([^\]]*)\]").unwrap();
        let listed: BTreeSet<String> = locked.captures(source).unwrap()[1].split(',').map(|id| id.trim().trim_matches('\'').to_string()).filter(|id| !id.starts_with("cloud")).collect();
        assert_eq!(listed, LOCKED.iter().map(|id| id.to_string()).collect::<BTreeSet<_>>());
    }
}
