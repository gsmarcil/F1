//! Reads what the web server already logs: its access log, and the same lines where a container's output is kept
//! (Docker's log files, a Kubernetes node's). It never sends a request and never reads a request body. Only
//! labels and counts leave this module: the request text stays on the machine.

use regex::Regex;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

pub const WEB_LOG_GLOBS: &[&str] = &["/var/log/nginx/*access*.log", "/var/log/apache2/*access*.log", "/var/log/httpd/*access*log", "C:\\inetpub\\logs\\LogFiles\\W3SVC*\\*.log"];
/// Where a container's output is kept on the machine that runs it. A web server in a container writes its access
/// log there, so one agent on the root machine can read them all.
pub const CONTAINER_LOG_GLOBS: &[&str] = &["/var/lib/docker/containers/*/*-json.log", "/var/log/pods/*/*/*.log"];
pub const WEB_ROOTS: &[&str] = &["/var/www", "/usr/share/nginx/html", "/srv/www", "C:\\inetpub\\wwwroot"];
pub const SCRIPT_EXTENSIONS: &[&str] = &[".php", ".phtml", ".phar", ".jsp", ".jspx", ".aspx", ".ashx", ".asp", ".cfm"];

struct Patterns {
    cri: Regex,
    combined: Regex,
    injection: Vec<(Regex, &'static str)>,
    shell_parameter: Regex,
    uploads: Regex,
    login_path: Regex,
    number: Regex,
}

fn patterns() -> &'static Patterns {
    static CELL: OnceLock<Patterns> = OnceLock::new();
    CELL.get_or_init(|| {
        let make = |pattern: &str| Regex::new(pattern).expect("a fixed pattern");
        Patterns {
            cri: make(r"^\S+ (?:stdout|stderr) [FP] (.*)$"),
            combined: make(r#"^(\S+) \S+ \S+ \[[^\]]*\] "([A-Z]+) (\S+)[^"]*" (\d{3})"#),
            // Labels only: the request text never leaves the device.
            injection: vec![
                (make(r"(?i)\bunion\b.{0,40}\bselect\b|'\s*or\s*'?\d+'?\s*=\s*'?\d|\bsleep\(\d+\)|\bwaitfor\s+delay\b|information_schema|;\s*drop\s+table"), "SQL injection"),
                (make(r"(?i)\.\./\.\./|\.\.\\\.\.\\|/etc/passwd|win\.ini|boot\.ini"), "path traversal"),
                (make(r"(?i)[;|`]\s*(cat|id|whoami|uname|wget|curl|nc|bash|sh)\b|\$\((id|whoami|cat)\b"), "command injection"),
                (make(r"(?i)\{\{\s*\d+\s*\*\s*\d+\s*\}\}|\$\{\s*\d+\s*\*\s*\d+\s*\}|<%=\s*\d+\s*\*"), "template injection"),
                (make(r"(?i)169\.254\.169\.254|metadata\.google\.internal|=(gopher|file|dict)://|=https?://(127\.0\.0\.1|localhost)\b"), "server-side request forgery"),
                (make(r#"(?i)\bO:\d{1,3}:"[a-z_\\][a-z0-9_\\]{0,80}":\d{1,3}:\{"#), "object injection"),
                (make(r" {50,}"), "a memory corruption probe"),
            ],
            shell_parameter: make(r"(?i)[?&](cmd|exec|command|shell|execute|run)="),
            // Where a site keeps what its visitors send it. Nothing there is meant to run on the server.
            uploads: make(r"/(uploads?|uploaded|user_?files)/"),
            login_path: make(r"(?i)/(wp-login\.php|login|signin|sign-in|logon|auth|authenticate|session|token|oauth/token)(/|\.|$)"),
            number: make(r"\d{1,12}"),
        }
    })
}

/// What one web client did, as a signal: (signal id, points before the learned policy, what is said about it).
pub type Mark = (&'static str, i64, String);

#[derive(Default)]
struct Client {
    order: u64,
    seen: f64,
    missing: HashMap<String, f64>,
    injection: Vec<(f64, &'static str, u16)>,
    logins: Vec<f64>,
    numbers: HashMap<String, HashMap<String, f64>>,
    shell: Vec<f64>,
    uploaded: Vec<f64>,
    errors: Vec<f64>,
}

#[derive(Default)]
pub struct WebWatch {
    pub logs: Vec<String>,
    pub roots: Vec<String>,
    offsets: HashMap<String, u64>,
    fields: HashMap<String, Vec<String>>,
    clients: HashMap<String, Client>,
    order: u64,
    known_scripts: Option<HashSet<String>>,
    scanned_at: f64,
    containers: bool,
    containers_at: f64,
}

fn wild(pattern: &[u8], name: &[u8]) -> bool {
    match pattern.split_first() {
        None => name.is_empty(),
        Some((b'*', rest)) => (0..=name.len()).any(|skip| wild(rest, &name[skip..])),
        Some((first, rest)) => name.first() == Some(first) && wild(rest, &name[1..]),
    }
}

/// The files a pattern names, sorted. `*` stands for any run of characters inside one name, never a leading dot.
pub fn glob(pattern: &str) -> Vec<String> {
    let windows = pattern.contains('\\');
    if windows != cfg!(windows) {
        return Vec::new();
    }
    let between = if windows { '\\' } else { '/' };
    let mut parts = pattern.split(between);
    let first = parts.next().unwrap_or("");
    let mut found: Vec<PathBuf> = vec![PathBuf::from(if first.is_empty() { between.to_string() } else { format!("{first}{between}") })];
    for part in parts {
        let mut next = Vec::new();
        for folder in &found {
            if !part.contains('*') {
                let whole = folder.join(part);
                if whole.exists() {
                    next.push(whole);
                }
                continue;
            }
            let Ok(entries) = std::fs::read_dir(folder) else { continue };
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                if !name.starts_with('.') && wild(part.as_bytes(), name.as_bytes()) {
                    next.push(folder.join(name));
                }
            }
        }
        found = next;
    }
    let mut names: Vec<String> = found.into_iter().map(|path| path.to_string_lossy().into_owned()).collect();
    names.sort();
    names
}

/// `+` is a space and `%41` is `A`; what is not valid text afterwards is replaced, never dropped.
pub fn unquote_plus(value: &str) -> String {
    let bytes = value.as_bytes();
    let hex = |byte: u8| (byte as char).to_digit(16).map(|digit| digit as u8);
    let (mut out, mut at) = (Vec::with_capacity(bytes.len()), 0);
    while at < bytes.len() {
        match bytes[at] {
            b'+' => out.push(b' '),
            b'%' if at + 2 < bytes.len() && hex(bytes[at + 1]).is_some() && hex(bytes[at + 2]).is_some() => {
                out.push(hex(bytes[at + 1]).unwrap_or(0) * 16 + hex(bytes[at + 2]).unwrap_or(0));
                at += 2;
            }
            other => out.push(other),
        }
        at += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn first_chars(value: &str, count: usize) -> &str {
    value.char_indices().nth(count).map(|(end, _)| &value[..end]).unwrap_or(value)
}

/// Split on every kind of line break (the set Python's `splitlines` uses), as the recorded steps expect.
fn lines(text: &str) -> Vec<&str> {
    let mut found = Vec::new();
    let (mut start, mut chars) = (0, text.char_indices().peekable());
    while let Some((at, letter)) = chars.next() {
        if matches!(letter, '\n' | '\r' | '\u{0b}' | '\u{0c}' | '\u{1c}' | '\u{1d}' | '\u{1e}' | '\u{85}' | '\u{2028}' | '\u{2029}') {
            found.push(&text[start..at]);
            let mut end = at + letter.len_utf8();
            if letter == '\r' && chars.peek().is_some_and(|(_, next)| *next == '\n') {
                chars.next();
                end += 1;
            }
            start = end;
        }
    }
    if start < text.len() {
        found.push(&text[start..]);
    }
    found
}

impl WebWatch {
    pub fn new(logs: Vec<String>, roots: Vec<String>) -> WebWatch {
        WebWatch { logs, roots, ..WebWatch::default() }
    }

    /// The logs and web folders this machine has, or `None` when it has neither and runs no containers.
    pub fn discover(now: f64) -> Option<WebWatch> {
        let logs: Vec<String> = WEB_LOG_GLOBS.iter().flat_map(|pattern| {
            let found = glob(pattern);
            found[found.len().saturating_sub(8)..].to_vec()
        }).collect();
        let roots: Vec<String> = WEB_ROOTS.iter().filter(|root| Path::new(root).is_dir()).map(|root| root.to_string()).collect();
        let hosts_containers = cfg!(unix) && (Path::new("/var/lib/docker").is_dir() || Path::new("/var/log").is_dir());
        if logs.is_empty() && roots.is_empty() && !hosts_containers {
            return None;
        }
        let mut watch = WebWatch::new(logs, roots);
        if hosts_containers {
            watch.containers = true;
            watch.find_containers(now);
        }
        Some(watch)
    }

    /// Container logs come and go with their containers: look for new ones every minute.
    fn find_containers(&mut self, now: f64) {
        self.containers_at = now;
        let have: HashSet<String> = self.logs.iter().cloned().collect();
        for pattern in CONTAINER_LOG_GLOBS {
            let found = glob(pattern);
            for log in &found[found.len().saturating_sub(200)..] {
                if !have.contains(log) {
                    self.logs.push(log.clone());
                }
            }
        }
        self.logs.retain(|log| Path::new(log).exists());
        let extra = self.logs.len().saturating_sub(400);
        self.logs.drain(..extra);
    }

    /// New complete lines since the last read. The first look at a file starts at its end.
    fn new_text(&mut self, path: &str) -> Option<String> {
        let size = std::fs::metadata(path).ok()?.len();
        let mut offset = match self.offsets.get(path).copied() {
            None => {
                self.offsets.insert(path.to_string(), size);
                return None;
            }
            Some(offset) => offset,
        };
        if size < offset {
            self.offsets.insert(path.to_string(), 0); // the log was rotated
            offset = 0;
        }
        if size == offset {
            return None;
        }
        let mut file = std::fs::File::open(path).ok()?;
        file.seek(SeekFrom::Start(offset)).ok()?;
        let mut data = Vec::new();
        file.take((size - offset).min(4 * 1024 * 1024)).read_to_end(&mut data).ok()?;
        let end = data.iter().rposition(|byte| *byte == b'\n')?;
        self.offsets.insert(path.to_string(), offset + end as u64 + 1);
        Some(String::from_utf8_lossy(&data[..end]).into_owned())
    }

    /// (client, method, target, status) from a combined-format line or an IIS W3C line.
    fn parse(&mut self, path: &str, line: &str) -> Option<(String, String, String, u16)> {
        let mut line = line.to_string();
        if line.starts_with("{\"log\":") {
            // Docker's log file: the container's line wrapped in JSON.
            let wrapped: serde_json::Value = serde_json::from_str(&line).ok()?;
            line = wrapped["log"].as_str().unwrap_or("").trim_end_matches('\n').to_string();
        } else if line.chars().next().is_some_and(|first| first.is_ascii_digit()) && first_chars(&line, 48).contains(" std") {
            // A Kubernetes node's log file: time, stream, flag, then the line.
            if let Some(inner) = patterns().cri.captures(&line).and_then(|found| found.get(1)).map(|inner| inner.as_str().to_string()) {
                line = inner;
            }
        }
        if line.starts_with('#') {
            if let Some(names) = line.strip_prefix("#Fields:") {
                self.fields.insert(path.to_string(), names.split_whitespace().map(str::to_string).collect());
            }
            return None;
        }
        if let Some(fields) = self.fields.get(path).filter(|fields| !fields.is_empty()) {
            let parts: Vec<&str> = line.split(' ').collect();
            if parts.len() != fields.len() {
                return None;
            }
            let get = |name: &str| fields.iter().position(|field| field == name).map(|at| parts[at]);
            let query = get("cs-uri-query").unwrap_or("-");
            let target = format!("{}{}", get("cs-uri-stem")?, if query == "-" || query.is_empty() { String::new() } else { format!("?{query}") });
            return Some((get("c-ip")?.to_string(), get("cs-method")?.to_string(), target, get("sc-status")?.trim().parse().ok()?));
        }
        let found = patterns().combined.captures(&line)?;
        Some((found[1].to_string(), found[2].to_string(), found[3].to_string(), found[4].parse().ok()?))
    }

    fn record(&mut self, client: &str, method: &str, target: &str, status: u16, now: f64) {
        if !self.clients.contains_key(client) {
            if self.clients.len() >= 4000 {
                // Full: the client seen longest ago makes room.
                if let Some(oldest) = self.clients.iter().min_by(|a, b| a.1.seen.total_cmp(&b.1.seen).then(a.1.order.cmp(&b.1.order))).map(|(name, _)| name.clone()) {
                    self.clients.remove(&oldest);
                }
            }
            self.order += 1;
            self.clients.insert(client.to_string(), Client { order: self.order, ..Client::default() });
        }
        let Some(state) = self.clients.get_mut(client) else { return };
        let known = patterns();
        state.seen = now;
        let twice = unquote_plus(&unquote_plus(target));
        let decoded = first_chars(&twice, 2000);
        let stem = decoded.split('?').next().unwrap_or("");
        if status == 403 || status == 404 {
            state.missing.insert(first_chars(stem, 200).to_string(), now);
        }
        if let Some((_, label)) = known.injection.iter().find(|(pattern, _)| pattern.is_match(decoded)) {
            state.injection.push((now, label, status));
        }
        if method == "POST" && known.login_path.is_match(stem) {
            state.logins.push(now);
        }
        if matches!(method, "POST" | "PUT" | "PATCH") && status >= 500 {
            state.errors.push(now);
        }
        if status < 400 {
            // Records that were actually served.
            if let Some(last) = known.number.find_iter(decoded).last() {
                let shape = known.number.replace_all(decoded, "#");
                state.numbers.entry(first_chars(&shape, 200).to_string()).or_default().insert(last.as_str().to_string(), now);
            }
        }
        let lowered = stem.to_lowercase();
        if SCRIPT_EXTENSIONS.iter().any(|extension| lowered.ends_with(extension)) && status == 200 {
            if known.shell_parameter.is_match(decoded) {
                state.shell.push(now);
            } else if known.uploads.is_match(&lowered) {
                state.uploaded.push(now);
            }
        }
    }

    fn scan_roots(&mut self) -> Vec<String> {
        let mut found: HashSet<String> = HashSet::new();
        let mut budget: i64 = 40000;
        for root in &self.roots {
            let mut queue = vec![(PathBuf::from(root), 0usize)];
            while let Some((folder, depth)) = queue.pop() {
                let Ok(entries) = std::fs::read_dir(&folder) else { continue };
                for entry in entries.flatten() {
                    let Ok(kind) = entry.file_type() else { continue };
                    if kind.is_dir() {
                        if depth < 8 {
                            queue.push((entry.path(), depth + 1));
                        }
                        continue;
                    }
                    budget -= 1;
                    let name = entry.file_name().to_string_lossy().to_lowercase();
                    if SCRIPT_EXTENSIONS.iter().any(|extension| name.ends_with(extension)) {
                        found.insert(entry.path().to_string_lossy().into_owned());
                    }
                }
                if budget <= 0 {
                    break;
                }
            }
        }
        let Some(known) = self.known_scripts.as_mut() else {
            self.known_scripts = Some(found); // what was there when the agent started is the baseline
            return Vec::new();
        };
        let fresh: BTreeSet<String> = found.difference(known).cloned().collect();
        known.extend(found);
        // A release drops many files at once; a planted web shell is one or two.
        if fresh.len() <= 3 { fresh.into_iter().collect() } else { Vec::new() }
    }

    /// Read what is new. Returns (each client worth a word, with what it did; new script files in a web folder).
    pub fn poll(&mut self, now: f64) -> (Vec<(String, Vec<Mark>)>, Vec<String>) {
        if self.containers && now - self.containers_at >= 60.0 {
            self.find_containers(now);
        }
        for path in self.logs.clone() {
            let Some(text) = self.new_text(&path) else { continue };
            for line in lines(&text) {
                if let Some((client, method, target, status)) = self.parse(&path, line) {
                    self.record(&client, &method, &target, status, now);
                }
            }
        }
        self.clients.retain(|_, state| now - state.seen <= 900.0);
        let mut results: Vec<(u64, String, Vec<Mark>)> = Vec::new();
        for (client, state) in self.clients.iter_mut() {
            state.missing.retain(|_, stamp| now - *stamp <= 60.0);
            state.injection.retain(|item| now - item.0 <= 300.0);
            state.logins.retain(|stamp| now - *stamp <= 60.0);
            state.shell.retain(|stamp| now - *stamp <= 300.0);
            state.uploaded.retain(|stamp| now - *stamp <= 300.0);
            state.errors.retain(|stamp| now - *stamp <= 60.0);
            for values in state.numbers.values_mut() {
                values.retain(|_, stamp| now - *stamp <= 60.0);
            }
            state.numbers.retain(|_, values| !values.is_empty());
            let mut marks: Vec<Mark> = Vec::new();
            if state.missing.len() >= 60 {
                marks.push(("web_fuzzing", 3, format!("asked for {} different pages that do not exist in one minute, the way a directory scanner works", state.missing.len())));
            }
            if state.injection.len() >= 3 {
                let labels: BTreeSet<&str> = state.injection.iter().map(|item| item.1).collect();
                marks.push(("web_injection_attempt", 3, format!("sent {} requests shaped like {}", state.injection.len(), labels.into_iter().take(3).collect::<Vec<_>>().join(" and "))));
                let answered = state.injection.iter().filter(|item| item.2 == 200 || item.2 >= 500).count();
                if answered > 0 {
                    marks.push(("web_injection_answered", 2, format!("got a normal or error answer to {answered} of those requests, so the application processed them")));
                }
            }
            let walked = state.numbers.values().map(HashMap::len).max().unwrap_or(0);
            if walked >= 40 {
                marks.push(("web_enumeration", 3, format!("walked through {walked} record numbers on one address pattern in one minute")));
            }
            if state.logins.len() >= 30 {
                marks.push(("web_login_burst", 3, format!("made {} sign-in attempts in one minute", state.logins.len())));
            }
            if !state.shell.is_empty() {
                marks.push(("web_shell_request", 3, format!("called a server-side script with a command parameter {} time(s) and was answered", state.shell.len())));
            } else if !state.uploaded.is_empty() {
                marks.push(("web_shell_request", 3, format!("was served a server-side script from an uploads folder {} time(s)", state.uploaded.len())));
            }
            if state.errors.len() >= 20 {
                marks.push(("web_error_burst", 2, format!("made the application fail {} times in one minute with requests that carry a body", state.errors.len())));
            }
            if !marks.is_empty() || crate::score::ADVISORY_ADDRESSES.contains(&client.as_str()) {
                results.push((state.order, client.clone(), marks));
            }
        }
        results.sort_by_key(|(order, _, _)| *order);
        let mut scripts = Vec::new();
        if !self.roots.is_empty() && now - self.scanned_at >= 60.0 {
            self.scanned_at = now;
            scripts = self.scan_roots();
        }
        (results.into_iter().map(|(_, client, marks)| (client, marks)).collect(), scripts)
    }
}
