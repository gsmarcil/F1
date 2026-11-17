//! The scorer: everything known about one program in, weighted signals and a level out.
//!
//! The tests replay recorded decisions (tests/fixtures/score.jsonl) and require the same signals, points,
//! evidence and level.

use crate::net::{is_internet, is_loopback};
use regex::Regex;
use std::collections::{BTreeSet, HashMap};
use std::sync::OnceLock;

pub const ADVISORY: &str = "FBI FLASH-20261113-001";
pub const ADVISORY_ADDRESSES: &[&str] = &[
    "38.244.50.120", "144.172.64.60", "144.172.64.99", "144.172.64.128", "187.15.88.186", "187.15.90.217", "187.15.89.186",
    "101.53.80.20", "205.214.59.31", "124.155.252.63", "154.201.79.246", "23.248.249.90", "23.158.220.98", "103.248.148.84",
    "203.160.133.172", "209.209.85.38", "199.19.95.66", "199.19.95.67", "199.19.95.68", "91.92.240.238", "85.11.168.45",
    "178.16.54.129", "31.77.229.35", "85.11.167.52",
];
pub const ADVISORY_DOMAINS: &[&str] = &["xcai.pro"];
pub const LLM_API_HOSTS: &[&str] = &["api.anthropic.com", "api.deepseek.com", "open.bigmodel.cn", "api.x.ai"];
pub const ADVISORY_TOOL_NAMES: &[&str] = &["chisel", "vshell", "adaptix"];
pub const DROP_HOSTS: &[&str] = &[
    "webhook.site", "pastebin.com", "paste.ee", "rentry.co", "transfer.sh", "file.io", "gofile.io", "catbox.moe",
    "0x0.st", "temp.sh", "ngrok.io", "ngrok-free.app", "ngrok.app", "trycloudflare.com", "loca.lt", "serveo.net",
    "localhost.run", "duckdns.org", "ddns.net", "no-ip.org", "hopto.org", "api.telegram.org",
];
/// Services that tell a program the public address of the machine it runs on. Bots and stealers ask on arrival.
pub const LOOKUP_HOSTS: &[&str] = &["api.ipify.org", "ifconfig.me", "icanhazip.com", "ip-api.com", "checkip.amazonaws.com", "ipinfo.io", "showip.net", "myexternalip.com", "ipecho.net"];
/// Remote-control tools, by the name of the program that runs (without `.exe`). Installed by their owner they
/// live in the program folders; a fake helpdesk has its victim start one from a download.
pub const REMOTE_TOOLS: &[&str] = &["anydesk", "teamviewer", "teamviewerqs", "rustdesk", "screenconnect.clientservice", "screenconnect.windowsclient", "client32", "meshagent",
    "supremo", "ultraviewer_desktop", "dwagent", "tacticalrmm", "ateraagent", "getscreen", "rutserv"];
/// The programs a person opens to type commands into, on Linux and macOS.
pub const TERMINALS: &[&str] = &["gnome-terminal-server", "gnome-terminal", "konsole", "xterm", "xfce4-terminal", "kitty", "alacritty", "tilix", "terminator", "lxterminal", "qterminal", "terminal", "iterm2"];
pub const TOR_NAMES: &[&str] = &["tor", "tor.exe"];
pub const TOR_SOCKS_PORTS: &[u16] = &[9050, 9150];
pub const TOR_RELAY_PORTS: &[u16] = &[9001, 9030];
pub const SOFTETHER_PREFIXES: &[&str] = &["vpnserver", "vpnclient", "vpnbridge", "vpncmd"];
pub const SOFTETHER_PORTS: &[u16] = &[992, 5555];
pub const REMOTE_ACCESS_PORTS: &[(u16, &str)] = &[(22, "SSH"), (23, "Telnet"), (445, "SMB"), (3389, "Remote Desktop"), (5900, "VNC"), (5985, "WinRM"), (5986, "WinRM")];
pub const USUAL_PORTS: &[u16] = &[80, 443, 853, 53, 22, 25, 110, 123, 143, 465, 587, 993, 995, 1194, 3478, 5222, 5223, 5228, 8080, 8443, 51820];

pub const SHELLS: &[&str] = &["cmd.exe", "powershell.exe", "pwsh.exe", "sh", "bash", "dash", "zsh", "ksh"];
pub const SCRIPT_HOSTS_MORE: &[&str] = &["wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "curl.exe", "wget.exe", "curl", "wget"];
pub const BROWSERS: &[&str] = &["chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe", "vivaldi.exe", "chrome", "firefox", "safari", "google chrome", "microsoft edge", "brave browser"];
pub const DOCUMENT_PARENTS_MORE: &[&str] = &[
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe", "acrord32.exe", "acrobat.exe",
    "foxitpdfreader.exe", "sumatrapdf.exe", "7zfm.exe", "7zg.exe", "winrar.exe", "thunderbird.exe",
    "microsoft word", "microsoft excel", "microsoft powerpoint", "microsoft outlook", "preview", "mail", "script editor",
];
pub const LOADER_TOOLS: &[&str] = &["msbuild.exe", "cmstp.exe"];
pub const LOADER_HOSTS: &[&str] = &["regsvr32.exe", "rundll32.exe", "mshta.exe"];
/// .NET tools that load whatever assembly they are handed: another program is easily run inside one.
pub const ASSEMBLY_HOSTS: &[&str] = &["regasm.exe", "regsvcs.exe", "installutil.exe"];
/// Windows system programs that start no shells of their own. A shell under one of them is what a privilege
/// escalation leaves, or a replaced accessibility tool on the sign-in screen.
pub const CHILDLESS_WINDOWS: &[&str] = &["winlogon.exe", "lsass.exe", "ctfmon.exe", "werfault.exe", "fontdrvhost.exe", "dwm.exe", "csrss.exe", "smss.exe"];
/// The helper the kernel calls for a network share's sign-in: it starts nothing.
pub const CHILDLESS_UNIX: &[&str] = &["cifs.upcall"];
/// The kernel starts a few helpers itself (module loading, crash handling). These it has no reason to start.
pub const KERNEL_STRANGERS: &[&str] = &["sh", "bash", "dash", "zsh", "ksh", "curl", "wget", "nc", "ncat", "socat"];
pub const CONTAINER_STORES: &[&str] = &["/var/lib/docker/overlay2/", "/var/lib/containers/storage/overlay/", "/var/lib/containerd/", "/run/containerd/"];
pub const WEB_SERVER_PREFIXES: &[&str] = &["w3wp", "httpd", "apache2", "nginx", "php-fpm", "php-cgi", "php", "tomcat", "java", "catalina"];
pub const SYSTEM_NAMES: &[&str] = &[
    "svchost.exe", "csrss.exe", "lsass.exe", "explorer.exe", "runtimebroker.exe", "services.exe", "winlogon.exe",
    "wininit.exe", "smss.exe", "dwm.exe", "taskhostw.exe", "conhost.exe", "dllhost.exe", "spoolsv.exe", "sihost.exe",
];
pub const MAIL_PARENTS: &[&str] = &["outlook.exe", "olk.exe", "hxoutlook.exe", "thunderbird.exe", "mail", "thunderbird"];
pub const ARCHIVE_PARENTS: &[&str] = &["7zfm.exe", "7zg.exe", "winrar.exe", "winzip64.exe", "peazip.exe", "bandizip.exe", "file-roller", "ark", "archive utility"];
pub const INTERPRETER_PREFIXES: &[&str] = &["python", "perl", "ruby", "php", "node"];
pub const DIRECTORY_TOOLS: &[&str] = &[
    "net.exe", "net1.exe", "nltest.exe", "dsquery.exe", "setspn.exe", "vssadmin.exe", "ntdsutil.exe", "reg.exe",
    "adfind.exe", "rubeus.exe", "mimikatz.exe", "procdump.exe", "procdump64.exe", "sharphound.exe",
];
pub const REMOTE_SESSION_PARENTS: &[(&str, &str)] = &[
    ("wsmprovhost.exe", "a remote PowerShell (WinRM) session"), ("wmiprvse.exe", "a remote WMI call"), ("psexesvc.exe", "a PsExec service"),
];
/// (kind, signal, points, what the account did). `%d` stands for the count.
pub const EVENT_SIGNALS: &[(&str, &str, i64, &str)] = &[
    ("kerberoast", "kerberoast_pattern", 5, "requested Kerberos service tickets with weak (RC4) encryption for %d different services in a few minutes, the pattern of Kerberoasting"),
    ("dcsync", "dcsync_pattern", 7, "asked a domain controller to replicate directory secrets %d time(s) from an account that is not a domain controller (DCSync)"),
    ("logon_failures", "logon_failure_burst", 5, "had %d failed sign-ins in a few minutes"),
    ("log_cleared", "audit_log_cleared", 5, "cleared the Security event log (%d time(s))"),
    ("privileged_group", "privileged_group_change", 5, "was added to a privileged group (%d change(s))"),
];
/// (signal, points, evidence). Each `%d` takes the next number.
pub const AGENT_SIGNALS: &[(&str, i64, &str)] = &[
    ("agent_command_stream", 3, "%d different commands were started one after another in %d seconds under the same program, the pace of an automated operator."),
    ("agent_retry_variation", 2, "%d commands in a row were near-copies of the one before, the way an automated operator retries a failed step with a small change."),
    ("agent_parallel_duplicates", 2, "The same command was started more than once at the same moment %d time(s), the way parallel sub-agents repeat each other."),
];

fn has(list: &[&str], name: &str) -> bool {
    list.contains(&name)
}

fn starts(name: &str, prefixes: &[&str]) -> bool {
    prefixes.iter().any(|prefix| name.starts_with(prefix))
}

pub fn is_shell(name: &str) -> bool {
    has(SHELLS, name)
}

pub fn is_script_host(name: &str) -> bool {
    has(SHELLS, name) || has(SCRIPT_HOSTS_MORE, name)
}

pub fn is_document_parent(name: &str) -> bool {
    has(BROWSERS, name) || has(DOCUMENT_PARENTS_MORE, name)
}

fn regex(cell: &'static OnceLock<Regex>, pattern: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(pattern).expect("a fixed pattern"))
}

fn labelled(cell: &'static OnceLock<Vec<(Regex, &'static str)>>, patterns: &[(&str, &'static str)]) -> &'static Vec<(Regex, &'static str)> {
    cell.get_or_init(|| patterns.iter().map(|(pattern, label)| (Regex::new(pattern).expect("a fixed pattern"), *label)).collect())
}

/// Labels only: the matched command line itself never leaves the device.
pub fn risky_commands() -> &'static Vec<(Regex, &'static str)> {
    static CELL: OnceLock<Vec<(Regex, &'static str)>> = OnceLock::new();
    labelled(&CELL, &[
        (r"(?i)(^|\s)-e(n|nc|nco|ncod|ncode|ncoded|ncodedc|ncodedcommand)?\s+[A-Za-z0-9+/=]{16,}", "encoded PowerShell command"),
        (r"(?i)FromBase64String|Invoke-Expression|(^|[\s;(|])IEX([\s(]|$)", "decode-and-run"),
        (r"(?i)DownloadString|DownloadFile|Invoke-WebRequest|Invoke-RestMethod", "download from a script"),
        (r"(?i)-w(indowstyle)?\s+hidden", "hidden window"),
        (r"(?i)(curl|wget)\b[^|;]{0,200}\|\s*(ba|z|da)?sh\b", "download piped to a shell"),
        (r"(?i)/dev/tcp/|\bnc\b[^|;]{0,80}\s-e\s|\bbash\s+-i\b", "reverse shell pattern"),
        (r"(?i)base64\s+(-d|--decode)\b[^|;]{0,80}\|\s*(ba|z|da)?sh\b", "decode piped to a shell"),
        (r#"(?i)mshta(\.exe)?[\s"']+(https?:|javascript:|vbscript:)|regsvr32(\.exe)?\s.*/i:\s*https?:|rundll32(\.exe)?\s.*(javascript:|https?:)"#, "a remote script run through a Windows system tool"),
        (r"(?i)certutil(\.exe)?\s.*-urlcache\b.*https?:|bitsadmin(\.exe)?\s.*/transfer\b.*https?:", "a download through a Windows system tool"),
        (r"(?i)(regsvr32|rundll32)(\.exe)?\s.*\\(Temp|AppData|Downloads|ProgramData|Users\\Public)\\", "a library loaded from a temporary or downloads folder"),
        (r"(?is)socket\b.{0,200}(dup2|pty\.spawn|subprocess)|fsockopen\(.{0,120}(exec|proc_open|shell_exec)", "a scripted reverse shell"),
        (r"(?i)\bxattr\s+-(d|c|cr|rc|dr|rd)\b.*(/tmp/|/var/folders/|/Downloads/)", "the download warning removed from a new file"),
        (r"(?i)\bosascript\b.*do shell script.*(curl|base64|/tmp/)", "a download run through AppleScript"),
        (r"(?i)forfiles(\.exe)?\s.*/c\s.*(mshta|powershell|curl|https?:)", "a command hidden behind a Windows system tool"),
        (r"(?i)mavinject(32|64)?(\.exe)?\s.*/injectrunning", "code injected into a running program with a Windows system tool"),
        (r"(?i)bcdedit(\.exe)?\s.*\bremovememory\b", "a boot setting that hides memory from Windows"),
        (r"(?i)msiexec(\.exe)?\s.*https?://.*\s[/-]q|msiexec(\.exe)?\s.*\s[/-]q\w*\s.*https?://", "an installer fetched from the internet and run silently"),
        (r"(?i)\brelease_agent\b|\bnotify_on_release\b", "a container escape through the cgroup release agent"),
        (r"(?i)\bsecurity\s+(dump-keychain|export\s+-k)\b", "the keychain copied out from a command line"),
        (r"(?i)\bnvme\s+(fw-download|fw-commit|fw-activate)\b", "firmware written to a storage drive"),
        (r"(?i)\binsmod\s+(\./|/tmp/|/var/tmp/|/dev/shm/|/home/|/root/)", "a kernel module loaded from a temporary or home folder"),
        (r"(?i)bcdedit(\.exe)?\s.*\b(testsigning|nointegritychecks)\s+on\b", "driver signature checks switched off for the next start"),
        (r"(?i)\bmokutil\s+--disable-validation\b|\bspctl\s+--(master|global)-disable\b", "the system's check of what may run switched off"),
        (r"(?i)\bflashrom\b.*\s(-w|--write)\b|chipsec_util(\.py)?\s+spi\s+(write|erase)\b", "the firmware chip written from the running system"),
    ])
}

fn credential_theft() -> &'static Vec<(Regex, &'static str)> {
    static CELL: OnceLock<Vec<(Regex, &'static str)>> = OnceLock::new();
    labelled(&CELL, &[
        (r"(?i)mimikatz|sekurlsa::|lsadump::|kerberos::(list|ptt|golden)", "a credential dumping tool"),
        (r"(?i)\brubeus\b|invoke-kerberoast|\bkerberoast\b|asreproast", "Kerberos ticket harvesting (Kerberoasting)"),
        (r"(?i)dcsync|secretsdump|invoke-dcsync", "a domain replication dump (DCSync)"),
        (r"(?i)ntdsutil\b.*\b(ifm|ntds)|\bntds\.dit\b", "a copy of the domain database"),
        (r"(?i)comsvcs(\.dll)?[ ,#]+.*minidump|procdump(64)?(\.exe)?\s.*lsass|\blsass\.dmp\b", "a memory dump of the sign-in process"),
        (r"(?i)reg(\.exe)?\s+save\s+hklm\\(sam|security|system)\b", "a copy of the local account database"),
    ])
}

fn directory_recon() -> &'static Vec<(Regex, &'static str)> {
    static CELL: OnceLock<Vec<(Regex, &'static str)>> = OnceLock::new();
    labelled(&CELL, &[
        (r"(?i)nltest(\.exe)?\s+/(dclist|domain_trusts|dsgetdc)", "domain controller lookup"),
        (r"(?i)\bnet1?(\.exe)?\s+(group|user|accounts|localgroup)\b.*\s/do(main)?\b", "domain account listing"),
        (r"(?i)\bdsquery(\.exe)?\s|\badfind(\.exe)?\b|setspn(\.exe)?\s+-(q|t)\b", "directory query tool"),
        (r#"(?i)get-ad(user|computer|group|groupmember|domain|trust|object)\b.*-filter\s+['"]?\*"#, "listing every directory object"),
        (r"(?i)sharphound|bloodhound|get-(domain|net)(user|computer|group|controller)|invoke-(sharefinder|userhunter)|get-lapspasswords?|ms-mcs-admpwd", "directory mapping tool"),
    ])
}

/// What an intruder types first after landing: who am I, what is this machine.
pub fn discovery() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    regex(&CELL, r#"(?i)(^|[\s;&|("'/\\])(whoami|systeminfo|ipconfig|ifconfig|hostname|uname\s+-a|id|net1?\s+(user|localgroup)|cat\s+/etc/(passwd|shadow)|quser|tasklist|ps\s+(aux|-ef))(\.exe)?(\s|$|[;&|)"'])"#)
}

fn windows_writable() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    regex(&CELL, r"(?i)\\(AppData|Temp|Tmp|Downloads|Users\\Public|ProgramData|Windows\\Tasks)\\|\\Users\\[^\\]+\\(Pictures|Music|Videos)\\")
}

pub fn unix_temp() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    regex(&CELL, r"^(/tmp/|/var/tmp/|/dev/shm/|/private/tmp/|/private/var/tmp/)")
}

pub fn unix_writable() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    regex(&CELL, r"^(/tmp/|/var/tmp/|/dev/shm/|/private/tmp/|/private/var/tmp/)|/(Downloads|\.cache)/")
}

/// A startup entry that fetches from a bare internet address: a name costs an intruder money and leaves a trail,
/// so their own entries often have none. Software from a vendor comes from a named host.
pub fn bare_download(words: &str) -> bool {
    static CELL: OnceLock<Regex> = OnceLock::new();
    regex(&CELL, r"(?i)\b(curl|wget)\b[^\n]{0,200}https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b").is_match(words)
}

/// A macOS startup entry that carries Apple's name but starts a program kept in a user's or a temporary folder.
/// Apple's own entries start programs from the system folders.
pub fn borrowed_name(place: &str, words: &str) -> bool {
    static CELL: OnceLock<Regex> = OnceLock::new();
    let user_program = regex(&CELL, r"<string>(/Users/|/private/tmp/|/tmp/|/private/var/folders/|/var/folders/)[^<]*</string>");
    if !(place.contains("/Library/LaunchAgents/") || place.contains("/Library/LaunchDaemons/")) {
        return false;
    }
    // Google's updater of that name starts from Google's own software-update folder and nowhere else.
    (words.contains("<string>com.apple.") && user_program.is_match(words)) || (words.contains("<string>com.google.keystone") && !words.contains("/Google/GoogleSoftwareUpdate/"))
}

/// A browser started where nobody can see it: off the screen and also headless or one dot in size, or carrying an
/// extension while hidden. Test tools hide a browser one way; a password stealer makes sure with two.
pub fn hidden_browser(line: &str) -> bool {
    static CELL: OnceLock<Regex> = OnceLock::new();
    let low = line.to_lowercase();
    if low.contains("--type=") {
        return false; // one of the browser's own helper processes
    }
    let off_screen = regex(&CELL, r"--window-position=-\d{4,}").is_match(&low);
    let (headless, dot, extension) = (low.contains("--headless"), low.contains("--window-size=1,1"), low.contains("--load-extension="));
    (off_screen && (headless || dot)) || (extension && (headless || off_screen))
}

/// Text that came from the device, made safe to show: control characters and angle brackets become spaces.
pub fn clean(value: &str, limit: usize) -> String {
    value.chars().map(|c| if c <= '\u{1f}' || c == '\u{7f}' || c == '<' || c == '>' { ' ' } else { c }).take(limit).collect()
}

fn host_matches<'a>(name: &str, suffixes: &[&'a str]) -> Option<&'a str> {
    let lowered = name.to_lowercase();
    let name = lowered.trim_matches('.');
    suffixes.iter().copied().find(|suffix| name == *suffix || name.ends_with(&format!(".{suffix}")))
}

pub fn user_writable(path: &str, system: &str) -> bool {
    !path.is_empty() && if system == "windows" { windows_writable().is_match(path) } else { unix_writable().is_match(path) }
}

fn system_path(path: &str, system: &str, system_root: &str) -> bool {
    let low = path.to_lowercase();
    if low.is_empty() || user_writable(path, system) {
        return false;
    }
    if system == "windows" {
        return low.starts_with(system_root) || low.starts_with("c:\\program files\\") || low.starts_with("c:\\program files (x86)\\");
    }
    starts(&low, &["/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/", "/usr/lib/", "/usr/libexec/", "/system/", "/applications/", "/opt/"])
}

pub fn level_for(score: i64, categories: usize) -> &'static str {
    if score <= 2 {
        "CLEAR"
    } else if score <= 4 {
        "WATCH"
    } else if score <= 6 || categories < 3 {
        "SUSPECT"
    } else {
        "HOSTILE"
    }
}

/// One outbound destination: (address, port) and the names known for it. A name that starts with `~` came from the
/// service's list of addresses that currently answer for a watched host.
#[derive(Clone, Debug, Default)]
pub struct Remote {
    pub address: String,
    pub port: u16,
    pub names: Vec<String>,
}

#[derive(Clone, Debug, Default)]
pub struct Detection {
    /// `None` when the antivirus gave no name at all.
    pub name: Option<String>,
    pub executed: bool,
    pub active: bool,
}

/// Everything the scorer may know about one program.
#[derive(Clone, Debug, Default)]
pub struct View {
    pub name: String,
    pub path: String,
    pub parent_name: String,
    /// "windows", "linux" or "macos".
    pub system: String,
    pub cmdline: Option<String>,
    /// (state, signer): state is "unsigned", "untrusted", "signed" or empty.
    pub signature: Option<(String, String)>,
    pub remotes: Vec<Remote>,
    /// (address, port) -> the time each new connection was first seen, in the order they were first contacted.
    pub contacts: Vec<(String, u16, Vec<f64>)>,
    /// local port -> who connected and when they were last seen.
    pub inbound: Vec<(u16, Vec<(String, f64)>)>,
    pub trusted: bool,
    pub baseline_days: f64,
    pub baseline_overlap: f64,
    pub detections: Vec<Detection>,
    /// Seconds since the program file appeared on this device, when that could be read.
    pub file_age: Option<f64>,
    /// Windows Security log summaries: (kind, count).
    pub events: Vec<(String, i64)>,
    /// The nearest ancestor that is not just another shell: who really started this.
    pub origin: String,
    /// Marks of an automated operator among this program's siblings: (signal, numbers for its evidence).
    pub agent: Vec<(String, Vec<i64>)>,
    pub exits: Vec<String>,
    /// Addresses another of the organisation's machines was attacked through, and why.
    pub fleet: Vec<(String, String)>,
    pub suspects: Vec<String>,
    /// Its parent accepts network connections.
    pub served: bool,
    /// That parent was just used for an attack, and this is not a command it normally runs.
    pub siege: bool,
    /// It runs as root, an ordinary user's program started it, and it never went through a program that grants root.
    pub jumped: bool,
    /// It is a root shell that a system program which never becomes one turned into directly.
    pub handed: bool,
    /// A keyboard this machine had never seen was plugged in seconds before it started.
    pub new_keyboard: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signal {
    pub id: String,
    pub points: i64,
    pub category: String,
    pub evidence: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outcome {
    pub score: i64,
    pub level: String,
    pub signals: Vec<Signal>,
    pub categories: Vec<String>,
}

fn fill(template: &str, numbers: &[i64]) -> String {
    let mut out = String::new();
    let mut next = numbers.iter();
    let mut rest = template;
    while let Some(at) = rest.find("%d") {
        out.push_str(&rest[..at]);
        out.push_str(&next.next().map(|number| number.to_string()).unwrap_or_default());
        rest = &rest[at + 2..];
    }
    out.push_str(rest);
    out
}

fn labels(patterns: &[(Regex, &'static str)], line: &str) -> Vec<&'static str> {
    let found: BTreeSet<&'static str> = patterns.iter().filter(|(pattern, _)| pattern.is_match(line)).map(|(_, label)| *label).collect();
    found.into_iter().collect()
}

/// The sum of floating point numbers as Python's `math.fsum` gives it for the values that occur here: carried
/// exactly through every addition (Neumaier), so a run of equal gaps averages to exactly that gap.
fn exact_sum(values: &[f64]) -> f64 {
    let (mut sum, mut carry) = (0.0f64, 0.0f64);
    for value in values {
        let next = sum + value;
        carry += if sum.abs() >= value.abs() { (sum - next) + value } else { (value - next) + sum };
        sum = next;
    }
    sum + carry
}

/// Score one program. `policy` shifts a positive signal by at most two points; `shapes` are pairs of signals the
/// service learned from confirmed attacks; `system_root` is the lower-cased Windows folder with a trailing backslash.
pub fn score_process(view: &View, now: f64, policy: &HashMap<String, i64>, shapes: &[(String, String)], system_root: &str) -> Outcome {
    let system = view.system.as_str();
    let name = view.name.to_lowercase();
    let name = name.as_str();
    let path = view.path.as_str();
    let parent = view.parent_name.to_lowercase();
    let source_name = if view.origin.is_empty() { view.parent_name.as_str() } else { view.origin.as_str() };
    let source = source_name.to_lowercase();
    let source = source.as_str();
    let browser = has(BROWSERS, name);
    let scripted = is_script_host(name) || (system != "windows" && starts(name, INTERPRETER_PREFIXES));
    let cmdline = view.cmdline.as_deref().filter(|line| !line.is_empty());
    let mut signals: Vec<Signal> = Vec::new();

    let add = |signals: &mut Vec<Signal>, signal: &str, points: i64, category: &str, evidence: &str| {
        let mut points = points;
        if points > 0 {
            points = (points + policy.get(signal).copied().unwrap_or(0)).clamp(0, 9);
            if points == 0 {
                return; // the owner's history says this signal means nothing on their devices
            }
        }
        signals.push(Signal { id: signal.to_string(), points, category: category.to_string(), evidence: clean(evidence, 200) });
    };

    // identity
    let (state, signer) = view.signature.clone().unwrap_or_default();
    if state == "unsigned" || state == "untrusted" {
        add(&mut signals, "unsigned_program", 2, "identity", "The program file has no valid publisher signature.");
    }
    let internet: Vec<&Remote> = view.remotes.iter().filter(|remote| is_internet(&remote.address)).collect();
    if system != "windows" && unix_temp().is_match(path) && !internet.is_empty() {
        add(&mut signals, "runs_from_temp", 3, "identity", "Runs from a temporary folder and talks to the internet.");
    } else if user_writable(path, system) {
        add(&mut signals, "user_writable_path", 1, "identity", "Runs from a folder any program can write to.");
    }
    if system == "windows" && has(SYSTEM_NAMES, name) && !path.is_empty() && !path.to_lowercase().starts_with(system_root) {
        add(&mut signals, "system_name_elsewhere", 3, "identity", "Named like a Windows system program but runs outside the Windows folder.");
    }
    if let Some(tool) = ADVISORY_TOOL_NAMES.iter().find(|item| name.contains(*item)) {
        add(&mut signals, "advisory_tool_name", 2, "identity", &format!("Named like {tool}, a tool {ADVISORY} reports on compromised hosts."));
    } else if starts(name, SOFTETHER_PREFIXES)
        && (path.to_lowercase().contains("softether") || starts(name, &["vpnbridge", "vpncmd"]) || view.remotes.iter().any(|remote| SOFTETHER_PORTS.contains(&remote.port)))
    {
        add(&mut signals, "advisory_tool_name", 2, "identity", &format!("This is SoftEther VPN, which {ADVISORY} reports intruders tunnelling through."));
    }

    // lineage
    if is_script_host(name) && is_document_parent(source) {
        add(&mut signals, "script_from_document", 3, "lineage", &format!("A script or download tool was started by {source_name}."));
    }
    let web_source = starts(source, WEB_SERVER_PREFIXES);
    let under_web = scripted && (web_source || view.served) && !starts(name, WEB_SERVER_PREFIXES);
    if under_web && !web_source {
        add(&mut signals, "shell_from_web_server", 3, "lineage", &format!("A shell was started by {source_name}, a program that accepts network connections: the pattern a web shell or command injection leaves."));
    } else if under_web {
        add(&mut signals, "shell_from_web_server", 3, "lineage", &format!("A shell was started by the web server process {source_name}, the pattern a web shell leaves."));
    }
    // Started by a system helper that starts nothing like it: what a privilege escalation leaves behind.
    let odd_parent = if system == "windows" {
        is_script_host(name) && has(CHILDLESS_WINDOWS, &parent)
    } else {
        has(CHILDLESS_UNIX, &parent) || (parent == "kthreadd" && (has(KERNEL_STRANGERS, name) || unix_temp().is_match(path) || starts(path, CONTAINER_STORES)))
    };
    if odd_parent {
        add(&mut signals, "helper_with_child", 5, "lineage", &format!("Started by {}, a system helper that has no reason to start it: the mark of a privilege escalation.", view.parent_name));
    }
    // A command window opened from where a person types, seconds after a keyboard this machine had never seen.
    let typed_into = if system == "windows" { is_script_host(name) && parent == "explorer.exe" } else { is_shell(name) && has(TERMINALS, &parent) };
    if view.new_keyboard && typed_into {
        add(&mut signals, "keyboard_injection", 5, "behaviour", "A keyboard this machine had never seen was plugged in, and seconds later a command window was opened: how a device that types by itself works.");
    }
    if view.handed {
        add(&mut signals, "privilege_jump", 6, "privilege", "A system program that gives root only after asking turned straight into a root shell: the mark of that program having been tampered with.");
    } else if view.jumped && system == "windows" {
        add(&mut signals, "privilege_jump", 6, "privilege", "Runs as SYSTEM, but an ordinary user's program started it: nothing that grants that stood between them.");
    } else if view.jumped {
        add(&mut signals, "privilege_jump", 6, "privilege", "Runs as root, but an ordinary user's program started it and it never went through a program that grants root.");
    }
    let remote_session = REMOTE_SESSION_PARENTS.iter().find(|(parent, _)| *parent == source).map(|(_, phrase)| *phrase);
    if let Some(line) = cmdline {
        if discovery().is_match(line) && (under_web || remote_session.is_some() || is_document_parent(source)) {
            add(&mut signals, "discovery_command", 2, "behaviour", "It ran a who-am-I or what-is-this-machine command, the first thing an intruder checks.");
        }
    }
    let hits = cmdline.map(|line| labels(risky_commands(), line)).unwrap_or_default();
    if !hits.is_empty() {
        add(&mut signals, "risky_command_line", 3, "lineage", &format!("Command line shows: {}.", hits.join(", ")));
    }
    // Automation where a person or a fixed script should be: only under a program an intruder lands in.
    if !view.agent.is_empty() && (under_web || (is_script_host(name) && (is_document_parent(source) || has(MAIL_PARENTS, source)))) {
        for (signal, numbers) in &view.agent {
            if let Some((_, points, template)) = AGENT_SIGNALS.iter().find(|(id, _, _)| id == signal) {
                add(&mut signals, signal, *points, "agent", &fill(template, numbers));
            }
        }
    }
    if !hits.is_empty() && is_script_host(name) && source == "explorer.exe" {
        add(&mut signals, "script_from_shortcut", 3, "lineage", "That command was started from a shortcut or the Run box, the way emailed shortcuts and paste-this-command lures work.");
    }
    if let (Some(line), true) = (cmdline, system == "windows") {
        let theft = labels(credential_theft(), line);
        let recon = labels(directory_recon(), line);
        if !theft.is_empty() {
            add(&mut signals, "credential_theft_tool", 6, "directory", &format!("Command line shows {}.", theft.join(", ")));
        }
        if !recon.is_empty() {
            add(&mut signals, "directory_recon", 2, "directory", &format!("Command line shows {}.", recon.join(", ")));
        }
    }
    if let (true, Some(phrase)) = (system == "windows" && (is_script_host(name) || has(DIRECTORY_TOOLS, name)), remote_session) {
        add(&mut signals, "remote_session_shell", 3, "lineage", &format!("Started inside {phrase}, the way an intruder moves between Windows machines."));
    }
    for (kind, count) in &view.events {
        if let Some((_, signal, points, phrase)) = EVENT_SIGNALS.iter().find(|(known, _, _, _)| known == kind) {
            add(&mut signals, signal, *points, "directory", &format!("The account {}.", fill(phrase, &[*count])));
        }
    }
    if !is_script_host(name) && user_writable(path, system) && (has(MAIL_PARENTS, source) || has(ARCHIVE_PARENTS, source)) {
        add(&mut signals, "program_from_attachment", 3, "lineage", &format!("A program in a downloads or temporary folder was started by {source_name}, the way an opened attachment runs."));
    }
    if let Some(age) = view.file_age {
        if age < 900.0 && user_writable(path, system) {
            let minutes = ((age / 60.0).floor() as i64).max(1);
            add(&mut signals, "fresh_file", 2, "identity", &format!("The program file appeared on this device {minutes} minute(s) before it ran."));
        }
    }

    let unseen = browser && cmdline.is_some_and(hidden_browser);
    if unseen {
        add(&mut signals, "hidden_browser", 5, "behaviour", "The browser was started where nobody can see it, the way a password stealer opens one to read what it has saved.");
    }
    let runs_others_code = scripted || unseen || has(LOADER_TOOLS, name) || has(ASSEMBLY_HOSTS, name) || has(DIRECTORY_TOOLS, name);
    let trusted_install = system_path(path, system, system_root) && !runs_others_code;
    if !trusted_install && has(REMOTE_TOOLS, name.strip_suffix(".exe").unwrap_or(name)) {
        add(&mut signals, "remote_control_tool", 3, "behaviour", &format!("{} is a remote-control tool, and it runs from outside the program folders: what a fake helpdesk has its victim start.", view.name));
    }

    // Tor: the client itself outside the system folders, or any other program routing through it
    if has(TOR_NAMES, name) {
        if (!internet.is_empty() || !view.inbound.is_empty()) && !trusted_install {
            add(&mut signals, "tor_routing", 2, "destinations", "A Tor client is running from outside the system folders.");
        }
    } else if !browser && view.remotes.iter().any(|remote| TOR_SOCKS_PORTS.contains(&remote.port) && is_loopback(&remote.address)) {
        add(&mut signals, "tor_routing", 3, "destinations", "Sends its traffic through the Tor proxy on this machine.");
    } else if !browser && !trusted_install && internet.iter().any(|remote| TOR_RELAY_PORTS.contains(&remote.port)) {
        add(&mut signals, "tor_routing", 1, "destinations", "Connects to a port Tor relays usually listen on.");
    }

    // A web application asked for this machine's cloud credentials: what request forgery and XML injection do.
    if view.remotes.iter().any(|remote| remote.address == "169.254.169.254") && (under_web || starts(name, WEB_SERVER_PREFIXES)) {
        add(&mut signals, "metadata_access_from_web", 2, "behaviour", "A web server process connected to the cloud metadata service, where instance credentials are handed out.");
    }

    // behaviour: system tools used the way malware loaders use them
    if name == "cmstp.exe" && is_script_host(&parent) {
        add(&mut signals, "system_tool_misuse", 5, "behaviour", &format!("cmstp.exe was started by {}, a known way to get administrator rights without a prompt.", view.parent_name));
    } else if has(ASSEMBLY_HOSTS, name) && !internet.is_empty() && (is_script_host(&parent) || parent.is_empty()) {
        let by = if view.parent_name.is_empty() { "an unknown program" } else { view.parent_name.as_str() };
        add(&mut signals, "system_tool_misuse", 4, "behaviour", &format!("{} is talking to the internet after being started by {by}, the pattern of a program hidden inside it.", view.name));
    } else if name == "msbuild.exe" && !internet.is_empty() && (is_script_host(&parent) || parent.is_empty()) {
        let by = if view.parent_name.is_empty() { "an unknown program" } else { view.parent_name.as_str() };
        add(&mut signals, "system_tool_misuse", 4, "behaviour", &format!("MSBuild.exe is talking to the internet after being started by {by}, the pattern of a program hidden inside it."));
    } else if has(LOADER_HOSTS, name) && !internet.is_empty() {
        add(&mut signals, "system_tool_misuse", 3, "behaviour", &format!("{} is talking to the internet, which it rarely has a reason to do.", view.name));
    }
    if let Some(found) = view.detections.first() {
        add(&mut signals, "antivirus_detection", 5, "antivirus", &format!("Windows Defender detected {}.", found.name.as_deref().unwrap_or("a threat")));
        if found.executed || found.active {
            add(&mut signals, "threat_executed", 3, "behaviour", "Windows Defender reports the threat ran or is still active on this device.");
        }
    }

    // destinations
    // A name comes from this machine's DNS cache, or (marked "~") from the service's watchlist of addresses
    // that currently answer for a host. An address can serve many sites, so that match is worth less.
    let matches = |suffixes: &[&str]| -> (Vec<String>, Vec<String>) {
        let exact: BTreeSet<String> = internet.iter().flat_map(|remote| remote.names.iter()).filter(|item| !item.starts_with('~') && host_matches(item, suffixes).is_some()).cloned().collect();
        let shared: BTreeSet<String> = internet.iter().flat_map(|remote| remote.names.iter()).filter(|item| item.starts_with('~') && host_matches(&item[1..], suffixes).is_some())
            .map(|item| item[1..].to_string()).filter(|item| !exact.contains(item)).collect();
        (exact.into_iter().collect(), shared.into_iter().collect())
    };
    let listed: Vec<String> = internet.iter().filter(|remote| ADVISORY_ADDRESSES.contains(&remote.address.as_str())).map(|remote| remote.address.clone()).collect::<BTreeSet<_>>().into_iter().collect();
    let (listed_names, listed_shared) = matches(ADVISORY_DOMAINS);
    if !listed.is_empty() || !listed_names.is_empty() {
        let both: Vec<String> = listed.iter().chain(listed_names.iter()).take(3).cloned().collect();
        add(&mut signals, "advisory_indicator", 5, "destinations", &format!("Connected to {}, listed in {ADVISORY}. The address may have been reassigned since; review before acting.", both.join(", ")));
    } else if let Some(first) = listed_shared.first() {
        add(&mut signals, "advisory_indicator", 3, "destinations", &format!("Connected to an address that currently answers for {first}, listed in {ADVISORY}. Other sites may share that address; review before acting."));
    }
    let mut shared: Vec<&str> = internet.iter().filter(|remote| view.fleet.iter().any(|(address, _)| *address == remote.address)).map(|remote| remote.address.as_str()).collect();
    shared.sort_unstable();
    if let Some(first) = shared.first() {
        let why = view.fleet.iter().rev().find(|(address, _)| address == first).map(|(_, why)| why.as_str()).unwrap_or("");
        let some: Vec<&str> = shared.iter().take(3).copied().collect();
        add(&mut signals, "fleet_indicator", 3, "destinations", &format!("Connected to {}: {}.", some.join(", "), clean(why, 90)));
    }
    if !browser {
        let (drops, shared_drops) = matches(DROP_HOSTS);
        if !drops.is_empty() {
            add(&mut signals, "drop_or_tunnel_host", 2, "destinations", &format!("Connected to a paste, file-drop or tunnel host: {}.", drops.iter().take(3).cloned().collect::<Vec<_>>().join(", ")));
        } else if !shared_drops.is_empty() {
            add(&mut signals, "drop_or_tunnel_host", 1, "destinations", &format!("Connected to an address that currently answers for {} (other sites may share it).", shared_drops.iter().take(3).cloned().collect::<Vec<_>>().join(", ")));
        }
        let (models, shared_models) = matches(LLM_API_HOSTS);
        if (!models.is_empty() || !shared_models.is_empty()) && !trusted_install {
            let named: Vec<String> = models.iter().chain(shared_models.iter()).take(2).cloned().collect();
            let by_address = if models.is_empty() { ", matched by address" } else { "" };
            add(&mut signals, "llm_api_host", 1, "destinations", &format!("Calls an AI model API ({}{by_address}) from a program outside the system folders.", named.join(", ")));
        }
        let (lookups, _) = matches(LOOKUP_HOSTS);
        if !lookups.is_empty() && !trusted_install {
            add(&mut signals, "address_lookup_host", 1, "destinations", &format!("Asked an outside service for this machine's public address ({}).", lookups.iter().take(2).cloned().collect::<Vec<_>>().join(", ")));
        }
        let odd: BTreeSet<u16> = internet.iter().map(|remote| remote.port).filter(|port| !USUAL_PORTS.contains(port)).collect();
        if !odd.is_empty() && !trusted_install {
            add(&mut signals, "unusual_port", 1, "destinations", &format!("Connects out on unusual port(s): {}.", odd.iter().take(4).map(|port| port.to_string()).collect::<Vec<_>>().join(", ")));
        }
    }

    // pattern
    for (address, port, times) in &view.contacts {
        let mut recent: Vec<f64> = times.iter().copied().filter(|stamp| now - stamp <= 1800.0).collect();
        recent.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let gaps: Vec<f64> = recent.windows(2).map(|pair| pair[1] - pair[0]).collect();
        if browser || !is_internet(address) || gaps.len() < 4 {
            continue;
        }
        let mean = exact_sum(&gaps) / gaps.len() as f64;
        let spread = (exact_sum(&gaps.iter().map(|gap| (gap - mean) * (gap - mean)).collect::<Vec<_>>()) / gaps.len() as f64).sqrt();
        if mean >= 20.0 && spread / mean < 0.2 {
            add(&mut signals, "beaconing", 3, "pattern", &format!("{} new connections to {address}:{port} about every {} seconds.", recent.len(), mean.trunc() as i64));
            break;
        }
    }
    if !browser {
        let burst: BTreeSet<&str> = view.contacts.iter().filter(|(address, _, times)| is_internet(address) && times.iter().any(|stamp| now - stamp <= 60.0)).map(|(address, _, _)| address.as_str()).collect();
        if burst.len() >= 20 {
            add(&mut signals, "fan_out", 2, "pattern", &format!("{} different internet addresses contacted in one minute.", burst.len()));
        }
    }

    // inbound: someone reaching this device
    for (port, sources) in &view.inbound {
        let live: BTreeSet<&str> = sources.iter().filter(|(address, seen)| now - seen <= 60.0 && is_internet(address)).map(|(address, _)| address.as_str()).collect();
        if let Some(hit) = live.iter().find(|address| ADVISORY_ADDRESSES.contains(*address)) {
            add(&mut signals, "inbound_advisory_indicator", 5, "inbound", &format!("Accepted a connection on port {port} from {hit}, listed in {ADVISORY}. The address may have been reassigned since; review before acting."));
        }
        if let Some((_, service)) = REMOTE_ACCESS_PORTS.iter().find(|(known, _)| known == port) {
            if live.len() >= 8 {
                add(&mut signals, "remote_access_burst", 5, "inbound", &format!("{} different internet addresses connected to {service} (port {port}) in one minute.", live.len()));
            }
        }
        let compromised: BTreeSet<&str> = sources.iter().filter(|(address, seen)| now - seen <= 60.0 && view.suspects.contains(address)).map(|(address, _)| address.as_str()).collect();
        if let Some(first) = compromised.iter().next() {
            if !signals.iter().any(|signal| signal.id == "inbound_from_suspect_peer") {
                add(&mut signals, "inbound_from_suspect_peer", 4, "inbound", &format!("Accepted a connection on port {port} from {first}, one of your own machines that has an open attack case."));
            }
        }
        let through_tor = live.iter().filter(|address| view.exits.iter().any(|exit| exit == *address)).count();
        if through_tor > 0 && !signals.iter().any(|signal| signal.id == "inbound_tor_exit") {
            add(&mut signals, "inbound_tor_exit", 2, "inbound", &format!("Accepted {through_tor} connection(s) on port {port} from Tor exit nodes."));
        }
    }

    // trust
    let attacked = signals.iter().any(|signal| signal.category == "inbound");
    if trusted_install && !attacked && state != "unsigned" && state != "untrusted" {
        let by = if signer.is_empty() { String::new() } else { format!(", signed by {signer}") };
        add(&mut signals, "installed_program", -3, "trust", &format!("Installed under a system or program folder{by}."));
    }
    if view.trusted {
        add(&mut signals, "owner_trusted", -5, "trust", "The owner marked this program as theirs.");
    } else if view.baseline_days >= 2.0 && view.baseline_overlap >= 0.8 {
        add(&mut signals, "known_baseline", -2, "trust", &format!("Seen on this device for {} days talking to the same places.", view.baseline_days.trunc() as i64));
    }

    // A combination this organisation's own confirmed attacks share, and nothing it marked as its own ever had.
    let fired: BTreeSet<String> = signals.iter().filter(|signal| signal.points > 0).map(|signal| signal.id.clone()).collect();
    for (first, second) in shapes {
        if fired.contains(first) && fired.contains(second) {
            add(&mut signals, "learned_attack_shape", 2, "learned", &format!("Matches a combination your confirmed attacks share: {} with {}.", first.replace('_', " "), second.replace('_', " ")));
            break;
        }
    }
    if view.siege && under_web && signals.iter().all(|signal| signal.id != "learned_attack_shape") {
        add(&mut signals, "learned_attack_shape", 2, "learned", "The program that started this was used for an attack minutes ago, and this is not a command it normally runs.");
    }

    let score = signals.iter().map(|signal| signal.points).sum();
    let categories: Vec<String> = signals.iter().filter(|signal| signal.points > 0).map(|signal| signal.category.clone()).collect::<BTreeSet<_>>().into_iter().collect();
    Outcome { score, level: level_for(score, categories.len()).to_string(), signals, categories }
}

/// Launch chains with almost no honest use: acted on without waiting for more evidence.
const CONTAIN_CHAINS: &[(&[&str], &str)] = &[
    (&["shell_from_web_server", "risky_command_line"], "a web server started a shell with a download-and-run or reverse-shell command"),
    (&["shell_from_web_server", "discovery_command"], "a web server started a shell that is exploring the machine"),
    (&["shell_from_web_server", "agent_command_stream"], "a web server is running a stream of commands at machine pace"),
    (&["script_from_document", "agent_command_stream"], "a document or mail program is running a stream of commands at machine pace"),
    (&["script_from_document", "risky_command_line"], "a document, mail or browser program started a script with a download-and-run command"),
    (&["script_from_shortcut", "risky_command_line"], "a shortcut or pasted command started a download-and-run script"),
    (&["program_from_attachment", "fresh_file"], "a program that just arrived was started from a mail or archive program"),
    (&["advisory_indicator", "runs_from_temp"], "a program in a temporary folder connected to an address listed in FBI FLASH-20261113-001"),
    (&["advisory_indicator", "unsigned_program"], "an unsigned program connected to an address listed in FBI FLASH-20261113-001"),
    (&["fleet_indicator", "runs_from_temp"], "a program in a temporary folder connected to an address another of your machines was attacked through"),
    (&["fleet_indicator", "unsigned_program"], "an unsigned program connected to an address another of your machines was attacked through"),
    (&["shell_from_web_server", "learned_attack_shape"], "a service that was just used for an attack started a command it does not normally run"),
    (&["credential_theft_tool"], "a credential theft command is running"),
    (&["remote_session_shell", "directory_recon"], "a remote session is mapping the domain"),
];

/// Why this program should be held or ended now, or "" to leave it running. Never for an attack on a service.
pub fn containment_reason(outcome: &Outcome) -> String {
    let found: BTreeSet<&str> = outcome.signals.iter().filter(|signal| signal.points > 0).map(|signal| signal.id.as_str()).collect();
    let on_a_service = ["antivirus_detection", "inbound_advisory_indicator", "remote_access_burst", "inbound_tor_exit", "inbound_from_suspect_peer",
        "kerberoast_pattern", "dcsync_pattern", "logon_failure_burst", "audit_log_cleared", "privileged_group_change"];
    if outcome.signals.iter().any(|signal| signal.id == "installed_program") || on_a_service.iter().any(|id| found.contains(id)) {
        return String::new();
    }
    if outcome.signals.iter().any(|signal| signal.id == "system_tool_misuse" && signal.points >= 4) && (outcome.level == "SUSPECT" || outcome.level == "HOSTILE") {
        return "a Windows system tool is being used the way a malware loader uses one".to_string();
    }
    for (wanted, reason) in CONTAIN_CHAINS {
        if wanted.iter().all(|id| found.contains(id)) {
            return reason.to_string();
        }
    }
    if outcome.level == "HOSTILE" {
        format!("it reached the hostile level on {}", outcome.categories.join(", "))
    } else {
        String::new()
    }
}

fn command_tokens(line: &str) -> BTreeSet<String> {
    static CELL: OnceLock<Regex> = OnceLock::new();
    regex(&CELL, r"[a-z0-9_./:-]{2,}").find_iter(&line.to_lowercase()).map(|found| found.as_str().to_string()).collect()
}

/// The marks an automated operator leaves among the commands started under one program.
/// `stream` is (time, command line) in the order they started. Returns (signal, numbers for its evidence).
pub fn agent_marks(stream: &[(f64, String)], now: f64, window: f64) -> Vec<(String, Vec<i64>)> {
    let recent: Vec<&(f64, String)> = stream.iter().filter(|(stamp, line)| now - stamp <= window && !line.is_empty()).collect();
    let mut marks = Vec::new();
    let distinct: BTreeSet<&str> = recent.iter().map(|(_, line)| line.as_str()).collect();
    if distinct.len() >= 6 {
        let latest = recent.iter().map(|(stamp, _)| *stamp).fold(f64::MIN, f64::max);
        let earliest = recent.iter().map(|(stamp, _)| *stamp).fold(f64::MAX, f64::min);
        let span = (latest - earliest).trunc() as i64;
        marks.push(("agent_command_stream".to_string(), vec![distinct.len() as i64, if span == 0 { 1 } else { span }]));
    }
    let mut near = 0;
    for pair in recent.windows(2) {
        let (before, after) = (&pair[0].1, &pair[1].1);
        let (a, b) = (command_tokens(before), command_tokens(after));
        if before != after && !a.is_empty() && !b.is_empty() && a.intersection(&b).count() as f64 / a.union(&b).count() as f64 >= 0.6 {
            near += 1;
        }
    }
    if near >= 3 {
        marks.push(("agent_retry_variation".to_string(), vec![near]));
    }
    let mut doubles = 0;
    let mut seen: HashMap<&str, f64> = HashMap::new();
    for (stamp, line) in recent.iter().map(|entry| (entry.0, entry.1.as_str())) {
        if let Some(before) = seen.get(line) {
            if stamp - before <= 3.0 {
                doubles += 1;
            }
        }
        seen.insert(line, stamp);
    }
    // One helper run over and over is a busy application, not a swarm: the repeats must sit in varied work.
    if doubles >= 2 && distinct.len() >= 4 {
        marks.push(("agent_parallel_duplicates".to_string(), vec![doubles]));
    }
    marks
}
