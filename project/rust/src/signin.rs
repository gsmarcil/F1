//! Failed SSH sign-ins on Linux: someone guessing passwords shows up in the sign-in log long before any program
//! starts. The log is read in both places a system may keep it (`/var/log/auth.log` or `/var/log/secure`, and
//! the journal), because a log file can be left behind by a system that no longer writes it. Each place is
//! counted by itself and the larger count stands, so a system that writes both is not counted twice. Only the
//! lines the SSH service itself wrote are counted, and an address with many failures in a few minutes is handed
//! back to be reported. Nothing is acted on here: a sign-in service is never touched.

use regex::Regex;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::OnceLock;

/// Failures are counted over this many seconds.
pub const WINDOW: f64 = 360.0;
/// This many failures from one address in the window are a burst: the number the Windows log watch uses.
pub const BURST: usize = 20;

/// One address that failed to sign in again and again.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Burst {
    pub address: String,
    pub count: usize,
    /// How many different account names it tried.
    pub accounts: usize,
    /// The account a sign-in from this address succeeded as, after the failures began; empty when none did.
    pub accepted: String,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Line {
    Failed(String, String),
    Invalid(String, String),
    Accepted(String, String),
}

fn pattern(cell: &'static OnceLock<Regex>, source: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(source).expect("a fixed pattern"))
}

/// What one message of the SSH service says, as (address, account). The account name is whatever the other side
/// typed, so every pattern is tied to the end of the line, where the service itself writes the address.
pub fn parse(message: &str) -> Option<Line> {
    static FAILED: OnceLock<Regex> = OnceLock::new();
    static INVALID: OnceLock<Regex> = OnceLock::new();
    static ACCEPTED: OnceLock<Regex> = OnceLock::new();
    let message = message.trim_end();
    let address = |found: &str| found.parse::<std::net::IpAddr>().ok().map(|address| address.to_string());
    let account = |found: &str| crate::score::clean(found, 40);
    if let Some(found) = pattern(&FAILED, r"^Failed (?:password|keyboard-interactive/pam) for (?:invalid user )?(.*) from (\S+) port \d+ ssh2$").captures(message) {
        return address(&found[2]).map(|address| Line::Failed(address, account(&found[1])));
    }
    if let Some(found) = pattern(&INVALID, r"^Invalid user (.*) from (\S+)(?: port \d+)?$").captures(message) {
        return address(&found[2]).map(|address| Line::Invalid(address, account(&found[1])));
    }
    if let Some(found) = pattern(&ACCEPTED, r"^Accepted \S+ for (\S+) from (\S+) port \d+ ssh2(?:: .*)?$").captures(message) {
        return address(&found[2]).map(|address| Line::Accepted(address, account(&found[1])));
    }
    None
}

/// The message of a line of a sign-in log file, when the SSH service wrote it. The service's name must come
/// straight after the time and the machine's name, so a line that only quotes one is not taken for one.
pub fn message(line: &str) -> Option<&str> {
    static CELL: OnceLock<Regex> = OnceLock::new();
    pattern(&CELL, r"^(?:[A-Z][a-z]{2}\s+\d+\s+[\d:]+|\d{4}-\d\d-\d\dT\S+)\s+\S+\s+sshd(?:-session)?\[\d+\]:\s(.*)$").captures(line).and_then(|found| found.get(1)).map(|found| found.as_str())
}

/// The failures of the last few minutes from one place.
#[derive(Default)]
pub struct SignIns {
    seen: VecDeque<(f64, Line)>,
}

/// The same address seen in two places: the larger count stands.
pub fn merge(first: Vec<Burst>, second: Vec<Burst>) -> Vec<Burst> {
    let mut found = first;
    for burst in second {
        match found.iter_mut().find(|known| known.address == burst.address) {
            Some(known) => {
                if burst.count > known.count {
                    (known.count, known.accounts) = (burst.count, burst.accounts);
                }
                if known.accepted.is_empty() {
                    known.accepted = burst.accepted;
                }
            }
            None => found.push(burst),
        }
    }
    found.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.address.cmp(&b.address)));
    found.truncate(8);
    found
}

/// The sign-in log of this machine: its files and its journal, and where each was read up to.
#[derive(Default)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub struct Log {
    from_files: SignIns,
    from_journal: SignIns,
    #[cfg(target_os = "linux")]
    files: Vec<(std::path::PathBuf, u64, u64)>,
    #[cfg(target_os = "linux")]
    since: f64,
}

impl SignIns {
    /// One message of the SSH service, read at this moment.
    pub fn note(&mut self, now: f64, message: &str) {
        if let Some(line) = parse(message) {
            self.seen.push_back((now, line));
            if self.seen.len() > 20_000 {
                self.seen.pop_front();
            }
        }
    }

    /// The addresses with a burst of failures in the window, the busiest first.
    pub fn bursts(&mut self, now: f64) -> Vec<Burst> {
        while self.seen.front().is_some_and(|(at, _)| now - at > WINDOW) {
            self.seen.pop_front();
        }
        let mut by_address: BTreeMap<&str, (usize, usize, BTreeSet<&str>, &str)> = BTreeMap::new();
        for (_, line) in &self.seen {
            match line {
                Line::Failed(address, account) => {
                    let entry = by_address.entry(address).or_default();
                    entry.0 += 1;
                    entry.2.insert(account);
                }
                Line::Invalid(address, account) => {
                    let entry = by_address.entry(address).or_default();
                    entry.1 += 1;
                    entry.2.insert(account);
                }
                Line::Accepted(address, account) => {
                    // Only a success that follows failures from the same address says anything.
                    if let Some(entry) = by_address.get_mut(address.as_str()) {
                        entry.3 = account;
                    }
                }
            }
        }
        // A wrong account name is written once as "Invalid user" and, where passwords are asked for, once more as
        // a failed password: the larger of the two counts is the number of attempts.
        let mut found: Vec<Burst> = by_address.into_iter().filter(|(_, entry)| entry.0.max(entry.1) >= BURST)
            .map(|(address, entry)| Burst { address: address.to_string(), count: entry.0.max(entry.1), accounts: entry.2.len(), accepted: entry.3.to_string() }).collect();
        found.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.address.cmp(&b.address)));
        found.truncate(8);
        found
    }

}

impl Log {
    /// Read what the SSH service has written since the last call, and say which addresses are in a burst.
    #[cfg(target_os = "linux")]
    pub fn poll(&mut self, now: f64) -> Vec<Burst> {
        use std::io::{Read, Seek, SeekFrom};
        use std::os::unix::fs::MetadataExt;
        for path in ["/var/log/auth.log", "/var/log/secure"] {
            let Ok(meta) = std::fs::metadata(path) else { continue };
            let at = match self.files.iter().position(|(known, _, _)| known.as_os_str() == path) {
                Some(at) => at,
                None => {
                    self.files.push((path.into(), meta.ino(), meta.len())); // the first look starts at the end: old lines are not news
                    continue;
                }
            };
            let (_, inode, position) = &mut self.files[at];
            if *inode != meta.ino() || meta.len() < *position {
                (*inode, *position) = (meta.ino(), 0); // the log was rotated: the new file is read from its start
            }
            let Ok(mut file) = std::fs::File::open(path) else { continue };
            let mut data = Vec::new();
            if file.seek(SeekFrom::Start(*position)).is_err() || file.take(1_048_576).read_to_end(&mut data).is_err() {
                continue;
            }
            let Some(end) = data.iter().rposition(|byte| *byte == b'\n') else { continue }; // a line still being written waits
            *position += end as u64 + 1;
            let whole = String::from_utf8_lossy(&data[..end]).into_owned();
            for line in whole.lines() {
                if let Some(said) = message(line) {
                    self.from_files.note(now, said);
                }
            }
        }
        // The journal, asked only for what the SSH service's own programs wrote. The first look starts now.
        if self.since > 0.0 {
            let from = format!("@{}", self.since.trunc() as i64 + 1);
            if let Some(raw) = crate::tool::run(&["journalctl", "-q", "--no-pager", "-o", "cat", "--since", &from, "_COMM=sshd", "_COMM=sshd-session"], None, std::time::Duration::from_secs(20)) {
                for line in raw.lines().take(20_000) {
                    self.from_journal.note(now, line);
                }
                self.since = now;
            }
        } else {
            self.since = now;
        }
        merge(self.from_files.bursts(now), self.from_journal.bursts(now))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_address_is_the_one_the_service_wrote_whatever_the_account_name_says() {
        assert_eq!(parse("Failed password for root from 198.51.100.7 port 51234 ssh2"), Some(Line::Failed("198.51.100.7".into(), "root".into())));
        assert_eq!(parse("Failed password for invalid user admin from 2001:db8::5 port 4 ssh2"), Some(Line::Failed("2001:db8::5".into(), "admin".into())));
        assert_eq!(parse("Invalid user oracle from 198.51.100.7 port 40000"), Some(Line::Invalid("198.51.100.7".into(), "oracle".into())));
        assert_eq!(parse("Accepted password for deploy from 198.51.100.7 port 40001 ssh2"), Some(Line::Accepted("198.51.100.7".into(), "deploy".into())));
        assert_eq!(parse("Accepted publickey for deploy from 198.51.100.7 port 40001 ssh2: ED25519 SHA256:abc"), Some(Line::Accepted("198.51.100.7".into(), "deploy".into())));
        // An account name written to look like another line: the real address is still the last one.
        assert_eq!(parse("Invalid user x from 203.0.113.1 port 1 from 198.51.100.7 port 40000"), Some(Line::Invalid("198.51.100.7".into(), "x from 203.0.113.1 port 1".into())));
        assert_eq!(parse("Failed publickey for root from 198.51.100.7 port 51234 ssh2"), None); // a client offering several keys
        assert_eq!(parse("Failed password for root from somewhere.example port 51234 ssh2"), None);
        assert_eq!(parse("Connection closed by 198.51.100.7 port 51234 [preauth]"), None);
    }

    #[test]
    fn only_lines_the_ssh_service_wrote_are_read_from_a_log_file() {
        assert_eq!(message("Nov  5 10:00:00 web1 sshd[812]: Invalid user a from 198.51.100.7 port 4"), Some("Invalid user a from 198.51.100.7 port 4"));
        assert_eq!(message("2026-11-05T10:00:00.123456+00:00 web1 sshd-session[812]: Invalid user a from 198.51.100.7 port 4"), Some("Invalid user a from 198.51.100.7 port 4"));
        assert_eq!(message("Nov  5 10:00:00 web1 app[9]: sshd[1]: Failed password for root from 198.51.100.7 port 4 ssh2"), None);
        assert_eq!(message("2026-11-05T10:00:00+00:00 web1 app[9]: note sshd[1]: Failed password for root from 198.51.100.7 port 4 ssh2"), None);
    }

    #[test]
    fn twenty_failures_in_six_minutes_are_a_burst_and_older_ones_are_forgotten() {
        let mut seen = SignIns::default();
        for number in 0..19 {
            seen.note(1000.0 + number as f64, &format!("Invalid user u{number} from 198.51.100.7 port 4"));
            seen.note(1000.0 + number as f64, &format!("Failed password for invalid user u{number} from 198.51.100.7 port 4 ssh2"));
        }
        seen.note(1001.0, "Failed password for root from 198.51.100.9 port 4 ssh2");
        assert!(seen.bursts(1020.0).is_empty(), "nineteen attempts, written twice each, are not twenty");
        seen.note(1020.0, "Invalid user last from 198.51.100.7 port 4");
        assert_eq!(seen.bursts(1021.0), vec![Burst { address: "198.51.100.7".into(), count: 20, accounts: 20, accepted: String::new() }]);
        seen.note(1022.0, "Accepted password for deploy from 198.51.100.7 port 9 ssh2");
        seen.note(1022.0, "Accepted password for other from 198.51.100.9 port 9 ssh2");
        assert_eq!(seen.bursts(1023.0)[0].accepted, "deploy");
        assert!(seen.bursts(1000.0 + WINDOW + 30.0).is_empty());
    }

    #[test]
    fn a_system_that_writes_the_log_in_two_places_is_not_counted_twice() {
        let burst = |address: &str, count: usize, accepted: &str| Burst { address: address.into(), count, accounts: 3, accepted: accepted.into() };
        let both = merge(vec![burst("198.51.100.7", 25, "")], vec![burst("198.51.100.7", 24, "deploy"), burst("198.51.100.9", 40, "")]);
        assert_eq!(both, vec![burst("198.51.100.9", 40, ""), burst("198.51.100.7", 25, "deploy")]);
    }
}
