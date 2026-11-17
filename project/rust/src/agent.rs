//! The agent around the watcher: where it keeps its state, how it talks to a Sentinel service, and what it does
//! with no service at all. It keeps agent.json, standalone.json, cases.jsonl, trusted.json and decisions.json in
//! its state folder.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

/// Signals added after the first release of the service, with the signal set that first knew each. A service
/// refuses a whole case over one signal it does not know, so it is sent only the ones it has said it knows.
pub const LATER_SIGNALS: &[(&str, u64)] = &[("helper_with_child", 2), ("privilege_jump", 2), ("signin_key_added", 2), ("hidden_browser", 2), ("remote_control_tool", 2), ("address_lookup_host", 2),
    ("boot_protection_off", 3), ("boot_entry_added", 3), ("firmware_downgraded", 3), ("firmware_changed_unannounced", 3), ("kernel_module_loose", 3), ("driver_checks_off", 3), ("boot_code_changed", 3), ("gateway_impersonated", 4), ("port_scan", 4), ("keyboard_injection", 5)];

/// The case as a service with this signal set can take it: without the signals it does not know, or `None`
/// when nothing that makes it a case is left.
pub fn known_to(mut case: Value, signal_set: u64) -> Option<Value> {
    let strange = |signal: &Value| signal["id"].as_str().is_some_and(|id| LATER_SIGNALS.iter().any(|(known, since)| *known == id && *since > signal_set));
    let Some(signals) = case["signals"].as_array() else { return Some(case) };
    if !signals.iter().any(strange) {
        return Some(case);
    }
    let kept: Vec<Value> = signals.iter().filter(|signal| !strange(signal)).cloned().collect();
    let score: i64 = kept.iter().filter_map(|signal| signal["points"].as_i64()).sum();
    if score < 5 {
        return None;
    }
    let categories: std::collections::BTreeSet<&str> = kept.iter().filter(|signal| signal["points"].as_i64().is_some_and(|points| points > 0)).filter_map(|signal| signal["category"].as_str()).collect();
    case["categories"] = serde_json::json!(categories);
    case["score"] = serde_json::json!(score);
    case["signals"] = serde_json::json!(kept);
    Some(case)
}

pub const PROTOCOL: &str = "sentinel-v1";
pub const MODES: &[&str] = &["report", "pause", "decide", "kill"];
const MAX_RESPONSE_BYTES: u64 = 256 * 1024;

pub fn now() -> f64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|since| since.as_secs_f64()).unwrap_or(0.0)
}

/// Random bytes from the operating system, as lower-case hex.
pub fn random_hex(bytes: usize) -> String {
    use ring::rand::SecureRandom;
    let mut buffer = vec![0u8; bytes];
    ring::rand::SystemRandom::new().fill(&mut buffer).expect("the operating system's random source");
    buffer.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A random number between `low` and `high`: so a fleet never moves in step.
pub fn jitter(low: f64, high: f64) -> f64 {
    let draw = u32::from_str_radix(&random_hex(4), 16).unwrap_or(0) as f64 / u32::MAX as f64;
    low + (high - low) * draw
}

fn is_hex(value: &str, length: usize) -> bool {
    value.len() == length && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// What a machine's label may contain: control characters and angle brackets become spaces.
pub fn label(value: &str) -> String {
    crate::score::clean(value, 80)
}

pub fn platform() -> Option<&'static str> {
    match std::env::consts::OS {
        "linux" => Some("linux"),
        "macos" => Some("macos"),
        "windows" => Some("windows"),
        _ => None,
    }
}

pub fn host_name() -> String {
    #[cfg(unix)]
    {
        let mut buffer = [0u8; 256];
        if unsafe { libc::gethostname(buffer.as_mut_ptr() as *mut libc::c_char, buffer.len()) } == 0 {
            let end = buffer.iter().position(|byte| *byte == 0).unwrap_or(buffer.len());
            return String::from_utf8_lossy(&buffer[..end]).into_owned();
        }
        String::from("machine")
    }
    #[cfg(not(unix))]
    {
        std::env::var("COMPUTERNAME").unwrap_or_else(|_| String::from("machine"))
    }
}

pub fn privileged() -> bool {
    #[cfg(unix)]
    {
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(windows)]
    {
        crate::win::privileged()
    }
    #[cfg(not(any(unix, windows)))]
    {
        false
    }
}

/// A moment as local time, to the minute.
pub fn stamp(at: i64) -> String {
    #[cfg(unix)]
    {
        let (moment, mut parts) = (at as libc::time_t, unsafe { std::mem::zeroed::<libc::tm>() });
        unsafe { libc::localtime_r(&moment, &mut parts) };
        format!("{:04}-{:02}-{:02} {:02}:{:02}", parts.tm_year + 1900, parts.tm_mon + 1, parts.tm_mday, parts.tm_hour, parts.tm_min)
    }
    #[cfg(not(unix))]
    {
        at.to_string()
    }
}

/// The folder this agent keeps its state in when none is given.
pub fn state_directory() -> PathBuf {
    if let Ok(given) = std::env::var("SENTINEL_STATE_DIR") {
        if !given.is_empty() {
            return PathBuf::from(given);
        }
    }
    if cfg!(windows) {
        return PathBuf::from(std::env::var("ProgramData").unwrap_or_else(|_| "C:\\ProgramData".into())).join("Sentinel");
    }
    if privileged() {
        return PathBuf::from("/var/lib/sentinel");
    }
    PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into())).join(".local/state/sentinel")
}

/// The service's address, checked: HTTPS only (plain HTTP only to this machine itself), and nothing but the address.
pub fn check_server(value: &str) -> Result<String, String> {
    let (scheme, rest) = value.split_once("://").ok_or("The server address must start with https://")?;
    let authority = rest.trim_end_matches('/');
    if authority.is_empty() || authority.contains(['/', '?', '#', '@']) {
        return Err("Give the server's address only, for example https://sentinel.example.org".into());
    }
    let host = if let Some(inner) = authority.strip_prefix('[') { inner.split(']').next().unwrap_or("") } else { authority.rsplit_once(':').map(|(host, port)| if port.bytes().all(|byte| byte.is_ascii_digit()) { host } else { authority }).unwrap_or(authority) };
    let local = matches!(host, "127.0.0.1" | "::1" | "localhost");
    if scheme != "https" && !(scheme == "http" && local) {
        return Err("The server address must start with https://".into());
    }
    Ok(format!("{scheme}://{authority}"))
}

/// A self-hosted service hands out '<enrolment key>.<SHA-256 of its certificate>'. Returns (key, pin).
pub fn split_key(key: &str) -> Result<(String, Option<String>), String> {
    match key.rsplit_once('.') {
        None => Ok((key.to_string(), None)),
        Some((secret, pin)) if is_hex(pin, 64) => Ok((secret.to_string(), Some(pin.to_string()))),
        Some(_) => Err("The enrolment key is damaged. Copy the whole join command again.".into()),
    }
}

#[derive(Debug)]
pub enum CallError {
    /// The service answered, with this status.
    Status(u16),
    /// The service could not be reached, or its answer was not understood.
    Other(String),
}

impl std::fmt::Display for CallError {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CallError::Status(status) => write!(out, "The service answered {status}."),
            CallError::Other(why) => write!(out, "{why}"),
        }
    }
}

/// A service that made its own certificate must present exactly the pinned one: it is compared whole, in place of
/// the certificate authorities, before anything is sent.
#[derive(Debug)]
struct Pinned {
    pin: String,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl rustls::client::danger::ServerCertVerifier for Pinned {
    fn verify_server_cert(&self, end_entity: &rustls::pki_types::CertificateDer<'_>, _intermediates: &[rustls::pki_types::CertificateDer<'_>], _name: &rustls::pki_types::ServerName<'_>, _ocsp: &[u8], _now: rustls::pki_types::UnixTime) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let seen: String = Sha256::digest(end_entity.as_ref()).iter().map(|byte| format!("{byte:02x}")).collect();
        // Compared in full, every time, with no early exit.
        let same = seen.len() == self.pin.len() && seen.bytes().zip(self.pin.bytes()).fold(0u8, |sum, (a, b)| sum | (a ^ b)) == 0;
        if same {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General("The service did not present the certificate this machine was told to expect.".into()))
        }
    }
    fn verify_tls12_signature(&self, message: &[u8], cert: &rustls::pki_types::CertificateDer<'_>, dss: &rustls::DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }
    fn verify_tls13_signature(&self, message: &[u8], cert: &rustls::pki_types::CertificateDer<'_>, dss: &rustls::DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

/// The TLS settings for one service: the pinned certificate when there is a pin, otherwise the public
/// certificate authorities (the Mozilla list, compiled in).
fn tls(pin: Option<&str>) -> Result<Arc<rustls::ClientConfig>, CallError> {
    let fail = |error: rustls::Error| CallError::Other(error.to_string());
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider.clone()).with_safe_default_protocol_versions().map_err(fail)?;
    Ok(Arc::new(match pin.filter(|pin| !pin.is_empty()) {
        Some(pin) => builder.dangerous().with_custom_certificate_verifier(Arc::new(Pinned { pin: pin.to_string(), provider })).with_no_client_auth(),
        None => builder.with_root_certificates(rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() }).with_no_client_auth(),
    }))
}

/// (https?, host, port) of a checked server address.
fn parts(server: &str) -> Result<(bool, String, u16), CallError> {
    let bad = || CallError::Other("The server address is not understood.".into());
    let (scheme, authority) = server.split_once("://").ok_or_else(bad)?;
    let secure = scheme == "https";
    let fallback = if secure { 443 } else { 80 };
    let (host, port) = if let Some(inner) = authority.strip_prefix('[') {
        let (host, rest) = inner.split_once(']').ok_or_else(bad)?;
        (host, match rest.strip_prefix(':') { Some(port) => port.parse().map_err(|_| bad())?, None => fallback })
    } else {
        match authority.rsplit_once(':') {
            Some((host, port)) if !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit()) => (host, port.parse().map_err(|_| bad())?),
            _ => (authority, fallback),
        }
    };
    if host.is_empty() || !host.is_ascii() {
        return Err(bad());
    }
    Ok((secure, host.to_string(), port))
}

/// Undo "chunked" transfer encoding. `None` when the body is not well formed.
fn unchunk(mut raw: &[u8]) -> Option<Vec<u8>> {
    let mut body = Vec::new();
    loop {
        let line = raw.windows(2).position(|pair| pair == b"\r\n")?;
        let size = usize::from_str_radix(std::str::from_utf8(&raw[..line]).ok()?.split(';').next()?.trim(), 16).ok()?;
        raw = &raw[line + 2..];
        if size == 0 {
            return Some(body);
        }
        if raw.len() < size + 2 {
            return None;
        }
        body.extend_from_slice(&raw[..size]);
        raw = &raw[size + 2..];
    }
}

/// One HTTP/1.1 exchange on a connection of its own: send, read the whole answer, close. Returns (status, body).
/// Redirects are never followed: one must never carry the device credential somewhere else.
fn exchange(server: &str, path: &str, payload: Option<&str>, token: Option<&str>, pin: Option<&str>, most: u64) -> Result<(u16, Vec<u8>), CallError> {
    use std::io::{Read, Write};
    use std::net::ToSocketAddrs;
    let other = |error: std::io::Error| CallError::Other(format!("The service could not be reached: {error}"));
    let (secure, host, port) = parts(server)?;
    let wait = Duration::from_secs(30);
    let mut last = None;
    let mut stream = None;
    for address in (host.as_str(), port).to_socket_addrs().map_err(other)?.take(4) {
        match std::net::TcpStream::connect_timeout(&address, wait) {
            Ok(open) => {
                stream = Some(open);
                break;
            }
            Err(error) => last = Some(error),
        }
    }
    let stream = stream.ok_or_else(|| last.map(other).unwrap_or_else(|| CallError::Other("The service's address was not found.".into())))?;
    stream.set_read_timeout(Some(wait)).map_err(other)?;
    stream.set_write_timeout(Some(wait)).map_err(other)?;
    let shown = if host.contains(':') { format!("[{host}]") } else { host.clone() };
    let mut request = format!("{} {path} HTTP/1.1\r\nHost: {shown}{}\r\nUser-Agent: sentinel-agent/{}\r\nAccept: application/json\r\nContent-Type: application/json\r\nConnection: close\r\n",
        if payload.is_some() { "POST" } else { "GET" }, if port == if secure { 443 } else { 80 } { String::new() } else { format!(":{port}") }, crate::VERSION);
    if let Some(token) = token {
        request.push_str(&format!("Authorization: Bearer {token}\r\n"));
    }
    if let Some(body) = payload {
        request.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    request.push_str("\r\n");
    request.push_str(payload.unwrap_or(""));
    let limit = most + 16 * 1024;
    let mut raw = Vec::new();
    if secure {
        let name = rustls::pki_types::ServerName::try_from(host.clone()).map_err(|_| CallError::Other("The server address is not understood.".into()))?;
        let session = rustls::ClientConnection::new(tls(pin)?, name).map_err(|error| CallError::Other(error.to_string()))?;
        let mut secured = rustls::StreamOwned::new(session, stream);
        secured.write_all(request.as_bytes()).map_err(other)?;
        // A service that closes without the closing notice has still sent everything it was going to.
        match Read::by_ref(&mut secured).take(limit).read_to_end(&mut raw) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof && !raw.is_empty() => {}
            Err(error) => return Err(other(error)),
        }
    } else {
        let mut plain = stream;
        plain.write_all(request.as_bytes()).map_err(other)?;
        Read::by_ref(&mut plain).take(limit).read_to_end(&mut raw).map_err(other)?;
    }
    let unclear = || CallError::Other("The service response was not understood.".into());
    let split = raw.windows(4).position(|four| four == b"\r\n\r\n").ok_or_else(unclear)?;
    let head = String::from_utf8_lossy(&raw[..split]).into_owned();
    let mut lines = head.split("\r\n");
    let status: u16 = lines.next().and_then(|line| line.split_whitespace().nth(1)).and_then(|code| code.parse().ok()).ok_or_else(unclear)?;
    let chunked = lines.any(|line| line.split_once(':').is_some_and(|(name, value)| name.eq_ignore_ascii_case("transfer-encoding") && value.to_ascii_lowercase().contains("chunked")));
    let body = if chunked { unchunk(&raw[split + 4..]).ok_or_else(unclear)? } else { raw[split + 4..].to_vec() };
    Ok((status, body))
}

/// One request to the service: GET when there is nothing to send, POST otherwise. The answer must be a JSON object.
pub fn call(server: &str, path: &str, payload: Option<&Value>, token: Option<&str>, pin: Option<&str>) -> Result<Value, CallError> {
    let server = check_server(server).map_err(CallError::Other)?;
    let body = payload.map(Value::to_string);
    let (status, raw) = exchange(&server, path, body.as_deref(), token, pin, MAX_RESPONSE_BYTES)?;
    if !(200..300).contains(&status) {
        return Err(CallError::Status(status));
    }
    if raw.len() as u64 > MAX_RESPONSE_BYTES {
        return Err(CallError::Other("The service response was too large.".into()));
    }
    match serde_json::from_slice::<Value>(&raw) {
        Ok(value) if value.is_object() => Ok(value),
        _ => Err(CallError::Other("The service response was not understood.".into())),
    }
}

/// A site's address as (the checked server address, the folder on it): `https://example.org/project` is
/// (`https://example.org`, `/project`). The server part obeys the same rules as a service's address.
pub fn split_site(site: &str) -> Result<(String, String), String> {
    let (scheme, rest) = site.split_once("://").ok_or("The site address must start with https://")?;
    let (authority, folder) = rest.split_once('/').unwrap_or((rest, ""));
    let folder = folder.trim_matches('/');
    if folder.contains(['?', '#', ' ', '\\']) || folder.split('/').any(|part| part == "..") {
        return Err("The site address is not understood.".into());
    }
    Ok((check_server(&format!("{scheme}://{authority}"))?, if folder.is_empty() { String::new() } else { format!("/{folder}") }))
}

/// Download one file from a site: its bytes, when the site answers 200 and the file is no larger than `most`.
/// The site's certificate is checked against the public certificate authorities; no credential is sent.
pub fn fetch(site: &str, path: &str, most: u64) -> Result<Vec<u8>, String> {
    let (site, folder) = split_site(site)?;
    let path = format!("{folder}{path}");
    let path = path.as_str();
    match exchange(&site, path, None, None, None, most) {
        Ok((200, body)) if body.len() as u64 <= most => Ok(body),
        Ok((200, _)) => Err(format!("{path} is larger than expected")),
        Ok((status, _)) => Err(format!("the site answered {status} for {path}")),
        Err(error) => Err(error.to_string()),
    }
}

/// The agent's own folder.
pub struct State {
    pub directory: PathBuf,
}

impl State {
    pub fn new(directory: Option<&str>) -> State {
        State { directory: directory.map(PathBuf::from).unwrap_or_else(state_directory) }
    }

    fn path(&self) -> PathBuf {
        self.directory.join("agent.json")
    }

    /// The saved enrolment, or `None` when this machine is not enrolled.
    pub fn load(&self) -> Result<Option<Value>, String> {
        let path = self.path();
        if std::fs::symlink_metadata(&path).map(|meta| meta.file_type().is_symlink()).unwrap_or(true) {
            return Ok(None);
        }
        let value: Value = std::fs::read(&path).ok().and_then(|raw| serde_json::from_slice(&raw).ok()).ok_or("The saved credential is damaged. Enrol again.")?;
        check_server(value["server"].as_str().unwrap_or(""))?;
        let pin = value["pin"].as_str().unwrap_or("");
        if !is_hex(value["token"].as_str().unwrap_or(""), 64) || !(pin.is_empty() || is_hex(pin, 64)) {
            return Err("The saved credential is damaged. Enrol again.".into());
        }
        Ok(Some(value))
    }

    pub fn make(&self) -> std::io::Result<()> {
        if !self.directory.exists() {
            std::fs::create_dir_all(&self.directory)?;
            private(&self.directory, 0o700);
        }
        Ok(())
    }

    pub fn save(&self, value: &Value) -> std::io::Result<()> {
        self.make()?;
        let temporary = self.directory.join(format!("agent-{}.tmp", random_hex(6)));
        std::fs::write(&temporary, value.to_string())?;
        private(&temporary, 0o600);
        std::fs::rename(&temporary, self.path())
    }

    pub fn remove(&self) {
        let _ = std::fs::remove_file(self.path());
    }
}

pub fn private(path: &Path, mode: u32) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
    }
}

fn seconds(value: &Value, low: i64, high: i64, fallback: i64) -> i64 {
    match value.as_i64() {
        Some(number) if value.is_i64() || value.is_u64() => number.clamp(low, high),
        _ => fallback,
    }
}

/// Join a Sentinel service. `patient` keeps trying, waiting longer each time, while the service is busy or
/// unreachable, so a whole fleet enrolling at once does not hammer it.
pub fn enroll(state: &State, server: &str, key: &str, mode: &str, name: Option<&str>, patient: bool) -> Result<Value, String> {
    if state.load()?.is_some() {
        return Err("This machine is already enrolled. Run `forget` first to enrol it again.".into());
    }
    let system = platform().ok_or("This platform is not supported.")?;
    let (key, pin) = split_key(key)?;
    let server = check_server(server)?;
    let payload = json!({"protocol": PROTOCOL, "key": key, "platform": system, "version": crate::VERSION,
        "label": label(name.map(str::to_string).unwrap_or_else(host_name).as_str()), "mode": if MODES.contains(&mode) { mode } else { "kill" }});
    let mut attempt = 0u32;
    let result = loop {
        match call(&server, "/v1/enroll", Some(&payload), None, pin.as_deref()) {
            Ok(value) => break value,
            Err(CallError::Status(status)) if patient && [429, 500, 502, 503, 504].contains(&status) => {}
            Err(CallError::Other(_)) if patient => {}
            Err(error) => return Err(error.to_string()),
        }
        // Wait longer each time, never in step.
        std::thread::sleep(Duration::from_secs_f64((5.0 * 2f64.powi(attempt.min(7) as i32)).min(600.0) * jitter(0.5, 1.5)));
        attempt += 1;
    };
    let token = result["token"].as_str().unwrap_or("");
    if result["protocol"] != PROTOCOL || !is_hex(token, 64) {
        return Err("The enrolment answer was not understood.".into());
    }
    let given = result["mode"].as_str().filter(|mode| MODES.contains(mode)).unwrap_or("report");
    let saved = json!({"server": server, "pin": pin.unwrap_or_default(), "token": token, "device_id": result["device_id"].as_str().unwrap_or(""), "salt": random_hex(32),
        "mode": given, "fallback": if result["fallback"] == "hold" { "hold" } else { "kill" },
        "decide_after": match result["decide_after"].as_i64() { Some(wait) if (5..=600).contains(&wait) => wait, _ => 20 },
        "state_key": result["state_key"].as_str().filter(|key| is_hex(key, 64)).unwrap_or(""),
        "interval": seconds(&result["interval"], 60, 3600, 300), "pulse": seconds(&result["pulse"], 30, 600, 60)});
    state.save(&saved).map_err(|error| error.to_string())?;
    Ok(saved)
}

/// The salt a machine with no service keys its cases with, made once.
pub fn standalone_salt(state: &State) -> std::io::Result<String> {
    state.make()?;
    let own = state.directory.join("standalone.json");
    if let Some(salt) = std::fs::read(&own).ok().and_then(|raw| serde_json::from_slice::<Value>(&raw).ok()).and_then(|value| value["salt"].as_str().map(str::to_string)).filter(|salt| is_hex(salt, 64)) {
        return Ok(salt);
    }
    let salt = random_hex(32);
    std::fs::write(&own, json!({"salt": salt}).to_string())?;
    private(&own, 0o600);
    Ok(salt)
}

/// The latest cases a machine with no service has kept.
pub fn local_cases(state: &State, count: usize) -> Vec<Value> {
    let Ok(raw) = std::fs::read_to_string(state.directory.join("cases.jsonl")) else { return Vec::new() };
    let lines: Vec<&str> = raw.lines().filter(|line| !line.trim().is_empty()).collect();
    lines[lines.len().saturating_sub(count)..].iter().filter_map(|line| serde_json::from_str(line).ok()).collect()
}

/// trust: this program is mine, leave it alone. stop / release: decide a program the agent paused.
pub fn local_decision(state: &State, key: &str, action: &str) -> Result<(), String> {
    if !is_hex(key, 32) {
        return Err("Give the case id shown by `cases` (32 characters).".into());
    }
    state.make().map_err(|error| error.to_string())?;
    let read = |path: &Path| -> Vec<Value> { std::fs::read(path).ok().and_then(|raw| serde_json::from_slice::<Value>(&raw).ok()).and_then(|value| value.as_array().cloned()).unwrap_or_default() };
    if action == "trust" {
        let path = state.directory.join("trusted.json");
        let mut keys: Vec<String> = read(&path).iter().filter_map(|item| item.as_str().map(str::to_string)).collect();
        keys.push(key.to_string());
        keys.sort();
        keys.dedup();
        std::fs::write(&path, json!(keys).to_string()).map_err(|error| error.to_string())?;
    }
    let path = state.directory.join("decisions.json");
    let mut wanted = read(&path);
    wanted.push(json!({"key": key, "action": if action == "trust" { "release" } else { action }}));
    std::fs::write(&path, Value::Array(wanted).to_string()).map_err(|error| error.to_string())
}

/// The owner says a case was an attack. The agent stops leaving that program alone; nothing else changes.
pub fn confirm(state: &State, key: &str) -> Result<(), String> {
    if !is_hex(key, 32) {
        return Err("Give the case id shown by `cases` (32 characters).".into());
    }
    state.make().map_err(|error| error.to_string())?;
    let path = state.directory.join("confirmed.json");
    let mut keys: Vec<String> = std::fs::read(&path).ok().and_then(|raw| serde_json::from_slice::<Vec<String>>(&raw).ok()).unwrap_or_default();
    keys.push(key.to_string());
    keys.sort();
    keys.dedup();
    let extra = keys.len().saturating_sub(2000);
    keys.drain(..extra);
    std::fs::write(&path, json!(keys).to_string()).map_err(|error| error.to_string())
}

/// One line of cases.jsonl for a case, and the line a person reads.
pub fn local_line(case: &Value) -> (Value, String) {
    let list = |key: &str| case[key].as_array().cloned().unwrap_or_default();
    let acted: Vec<String> = list("actions").iter().filter_map(|action| action["action"].as_str().map(str::to_string)).collect();
    let signals: Vec<String> = list("signals").iter().filter(|signal| signal["points"].as_i64().unwrap_or(0) > 0).filter_map(|signal| signal["id"].as_str().map(str::to_string)).collect();
    let line = json!({"at": now().trunc() as i64, "key": case["key"], "level": case["level"], "score": case["score"], "name": case["name"], "path": case["path"].as_str().unwrap_or(""),
        "parent": case["parent"].as_str().unwrap_or(""), "signals": signals, "actions": acted,
        "remotes": list("remotes").iter().filter_map(|remote| remote["address"].as_str().map(str::to_string)).collect::<Vec<_>>(), "cleanup": list("cleanup"),
        "held": case["held"].as_str().unwrap_or("")});
    let joined = acted.concat();
    let what = if joined.contains("stopped") { "STOPPED" } else if joined.contains("paused") { "PAUSED" } else { "flagged" };
    let said = format!("garrett: {what} {} ({}) case {}: {}", case["name"].as_str().unwrap_or(""), case["level"].as_str().unwrap_or(""), case["key"].as_str().unwrap_or(""), signals.join(", "));
    (line, said)
}

/// What is sent with every report.
pub fn report_payload(system: &str, cases: &[Value], status: &Value, results: &[Value], exits_have: &str, mesh: &Value, have: &str) -> Value {
    let count = |key: &str| status[key].as_i64().unwrap_or(0);
    json!({"protocol": PROTOCOL, "version": crate::VERSION, "platform": system, "cases": cases, "results": results, "exits_have": exits_have, "mesh": mesh,
        "watching": {"processes": count("processes"), "connections": count("connections"), "tracked": count("tracked")}, "have": have})
}
