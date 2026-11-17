//! Turning the system's own tools' output into processes and connections: `ss` on Linux, `lsof` and `ps` on macOS.
//! Held to recorded answers (tests/fixtures/parse.jsonl).

use crate::net;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

/// One running program as the sensors report it.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Proc {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub path: String,
    /// When it started, in the system's own units; 0 where the system does not say.
    pub started: u64,
}

/// One TCP connection a program holds.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Conn {
    pub pid: u32,
    pub lport: u32,
    pub raddr: String,
    pub rport: u32,
    /// True when the other side connected to this machine.
    pub inbound: bool,
    pub laddr: String,
}

impl Conn {
    pub fn new(pid: u32, lport: u32, raddr: &str, rport: u32, inbound: bool, laddr: &str) -> Conn {
        Conn { pid, lport, raddr: plain_address(raddr), rport, inbound, laddr: if laddr.is_empty() { String::new() } else { plain_address(laddr) } }
    }
}

/// An address in its usual written form, with IPv4 written inside IPv6 turned back into IPv4. Anything that is not
/// an address is returned as it came.
pub fn plain_address(address: &str) -> String {
    net::parse(address).map(|value| value.to_string()).unwrap_or_else(|| address.to_string())
}

/// "host:port" or "[host%zone]:port" -> (host, port). A port that is not a number is 0.
pub fn split_endpoint(value: &str) -> (String, u32) {
    let (host, port) = match value.rfind(':') {
        Some(at) => (&value[..at], &value[at + 1..]),
        None => ("", value),
    };
    let host = host.trim_matches(|c| c == '[' || c == ']').split('%').next().unwrap_or("");
    (host.to_string(), if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) { port.parse().unwrap_or(0) } else { 0 })
}

fn pids_in(line: &str) -> Vec<u32> {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| Regex::new(r"pid=(\d+)").expect("a fixed pattern")).captures_iter(line).filter_map(|found| found[1].parse().ok()).collect()
}

/// `ss -H -tanp`: one row per TCP socket. Other users' sockets carry no pid unless run as root.
pub fn parse_ss(raw: &str) -> Vec<Conn> {
    let mut rows: Vec<(String, u32, u32, String, u32, String)> = Vec::new();
    for line in raw.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 || ["TIME-WAIT", "CLOSED", "UNCONN", "SYN-RECV"].contains(&parts[0]) {
            continue;
        }
        let ((laddr, lport), (raddr, rport)) = (split_endpoint(parts[3]), split_endpoint(parts[4]));
        // A socket handed to a child lists every holder: the shell and what it started both own the connection.
        let mut holders = pids_in(line);
        if holders.is_empty() {
            holders.push(0);
        }
        for pid in holders {
            rows.push((parts[0].to_string(), pid, lport, raddr.clone(), rport, laddr.clone()));
        }
    }
    let listening: HashSet<(u32, u32)> = rows.iter().filter(|row| row.0 == "LISTEN").map(|row| (row.1, row.2)).collect();
    let mut owners: HashMap<u32, u32> = HashMap::new();
    for row in rows.iter().filter(|row| row.0 == "LISTEN" && row.1 != 0) {
        owners.insert(row.2, row.1);
    }
    // A connection the service already hung up on has no owner left: it still counts against the listener.
    rows.iter().filter(|row| row.0 != "LISTEN" && row.4 != 0).map(|(_, pid, lport, raddr, rport, laddr)| {
        let owner = if *pid != 0 { *pid } else { owners.get(lport).copied().unwrap_or(0) };
        Conn::new(owner, *lport, raddr, *rport, listening.contains(&(*pid, *lport)) || owners.contains_key(lport), laddr)
    }).collect()
}

/// The programs that accept connections, from the same `ss` output.
pub fn listening_pids(raw: &str) -> HashSet<u32> {
    raw.lines().filter(|line| line.starts_with("LISTEN")).flat_map(pids_in).collect()
}

/// `lsof -nP -iTCP -F pcnT`: field output, one letter per line.
pub fn parse_lsof(raw: &str) -> Vec<Conn> {
    let mut rows: Vec<(String, u32, u32, String, u32, String)> = Vec::new();
    let (mut pid, mut name, mut state) = (0u32, String::new(), String::new());
    let flush = |rows: &mut Vec<(String, u32, u32, String, u32, String)>, pid: u32, name: &str, state: &str| {
        if !name.is_empty() && !["", "CLOSED", "TIME_WAIT", "SYN_RCVD"].contains(&state) {
            let (local, remote) = match name.find("->") {
                Some(at) => (&name[..at], &name[at + 2..]),
                None => (name, ""),
            };
            let (laddr, lport) = split_endpoint(local);
            let (raddr, rport) = if remote.is_empty() { (String::new(), 0) } else { split_endpoint(remote) };
            rows.push((state.to_string(), pid, lport, raddr, rport, laddr));
        }
    };
    for line in raw.lines() {
        if line.starts_with('p') || line.starts_with('f') {
            flush(&mut rows, pid, &name, &state);
            name.clear();
            state.clear();
            if line.starts_with('p') && line.len() > 1 && line[1..].chars().all(|c| c.is_ascii_digit()) {
                pid = line[1..].parse().unwrap_or(0);
            }
        } else if let Some(rest) = line.strip_prefix('n') {
            name = rest.to_string();
        } else if let Some(rest) = line.strip_prefix("TST=") {
            state = rest.to_string();
        }
    }
    flush(&mut rows, pid, &name, &state);
    let listening: HashSet<(u32, u32)> = rows.iter().filter(|row| row.0 == "LISTEN").map(|row| (row.1, row.2)).collect();
    rows.iter().filter(|row| row.0 != "LISTEN" && row.4 != 0).map(|(_, owner, lport, raddr, rport, laddr)| Conn::new(*owner, *lport, raddr, *rport, listening.contains(&(*owner, *lport)), laddr)).collect()
}

/// `ps -axo pid=,ppid=,comm=`: every process with its parent and program path.
pub fn parse_ps(raw: &str) -> Vec<Proc> {
    static CELL: OnceLock<Regex> = OnceLock::new();
    let pattern = CELL.get_or_init(|| Regex::new(r"^\s*(\d+)\s+(\d+)\s+(.+)$").expect("a fixed pattern"));
    let mut found: Vec<Proc> = Vec::new();
    for line in raw.lines() {
        if let Some(parts) = pattern.captures(line) {
            let (Ok(pid), Ok(ppid)) = (parts[1].parse::<u32>(), parts[2].parse::<u32>()) else { continue };
            let path = parts[3].trim();
            let name = path.rsplit('/').next().unwrap_or(path);
            let entry = Proc { pid, ppid, name: name.to_string(), path: if path.starts_with('/') { path.to_string() } else { String::new() }, started: 0 };
            match found.iter_mut().find(|item| item.pid == pid) {
                Some(old) => *old = entry, // the same id listed twice: the later line stands
                None => found.push(entry),
            }
        }
    }
    found
}
