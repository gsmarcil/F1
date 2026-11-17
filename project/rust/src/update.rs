//! Keeping itself current. A sentinel that is installed and forgotten has to stay the best version there is, so
//! a few times a day the agent asks the official site whether a newer one is out, and installs it by itself.
//!
//! Nothing is trusted because of where it came from. The site publishes a short list, `update.txt`: the version,
//! and the SHA-256 of every program file of that version. The list is signed with a key that is kept off the
//! site and off GitHub, and the public half is compiled in below. The agent installs a program file only when
//! the list's signature is good, the list names a version newer than this one, the file matches the list, and
//! the file, run once, says it is that version. Whoever takes over the site can therefore publish nothing this
//! agent will run, and an old list replayed later is ignored.
//!
//! Where the Debian package is installed, apt does the installing (from the same signed repository), so the
//! package manager's record stays true. Everywhere else the agent swaps its own program file and starts again.

use ring::signature::{UnparsedPublicKey, ED25519};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// The official site.
pub const SOURCE: &str = "https://gary23w.github.io/sentinels";
/// The public half of the key that signs `update.txt`.
const KEY: &str = "6404e6be33e1f94de39079c51e22bd0b592586a24f2a5b5590ffce7d8888a984";
/// A second key, only in a program built for a test of the update itself. Published builds never have one.
const TEST_KEY: Option<&str> = option_env!("GARRETT_TEST_UPDATE_KEY");

fn unhex(text: &str) -> Option<Vec<u8>> {
    let text = text.trim();
    if text.len() % 2 != 0 || !text.is_ascii() {
        return None;
    }
    (0..text.len()).step_by(2).map(|at| u8::from_str_radix(&text[at..at + 2], 16).ok()).collect()
}

/// True when `signature` (written as hex) is this project's signature over exactly these bytes.
pub fn signed(list: &[u8], signature: &[u8]) -> bool {
    let Some(signature) = std::str::from_utf8(signature).ok().and_then(unhex).filter(|bytes| bytes.len() == 64) else { return false };
    [Some(KEY), TEST_KEY].into_iter().flatten().filter_map(unhex).any(|key| UnparsedPublicKey::new(&ED25519, key).verify(list, &signature).is_ok())
}

/// What the site says is current: the version, and (SHA-256, name) of each of its program files.
#[derive(Debug, PartialEq)]
pub struct Listed {
    pub version: String,
    pub files: Vec<(String, String)>,
}

fn numbers(version: &str) -> Option<Vec<u64>> {
    let parts: Option<Vec<u64>> = version.split('.').map(|part| part.parse().ok()).collect();
    parts.filter(|parts| (1..=4).contains(&parts.len()))
}

/// The first line is `garrett <version>`; every other line is a SHA-256 and a file name.
pub fn read(text: &str) -> Option<Listed> {
    let mut lines = text.lines();
    let version = lines.next()?.strip_prefix("garrett ")?.trim().to_string();
    numbers(&version)?;
    let mut files = Vec::new();
    for line in lines.filter(|line| !line.trim().is_empty()) {
        let (sum, name) = line.split_once("  ")?;
        if sum.len() != 64 || !sum.bytes().all(|byte| byte.is_ascii_hexdigit()) || name.is_empty() || name.contains(['/', '\\']) {
            return None;
        }
        files.push((sum.to_ascii_lowercase(), name.to_string()));
    }
    Some(Listed { version, files })
}

/// True when `candidate` is a later version than `current`. Anything that is not a plain version is not later.
pub fn newer(candidate: &str, current: &str) -> bool {
    match (numbers(candidate), numbers(current)) {
        (Some(candidate), Some(current)) => candidate > current,
        _ => false,
    }
}

/// The program file published for this kind of machine.
pub fn file_name() -> Option<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => Some("garrett-linux-x86_64"),
        ("linux", "aarch64") => Some("garrett-linux-aarch64"),
        ("linux", "arm") => Some("garrett-linux-armv7"),
        ("macos", _) => Some("garrett-macos"),
        ("windows", "x86_64") => Some("garrett-windows.exe"),
        _ => None,
    }
}

/// Where updates come from: the official site, unless a test names another. Whatever is named, the list still
/// has to carry this project's signature.
pub fn source() -> String {
    std::env::var("GARRETT_UPDATE_BASE").ok().filter(|value| !value.is_empty()).unwrap_or_else(|| SOURCE.to_string())
}

/// Ask the site what is current. `Ok(None)` when this agent already is.
pub fn check(base: &str) -> Result<Option<Listed>, String> {
    let list = crate::agent::fetch(base, "/update.txt", 65_536)?;
    let signature = crate::agent::fetch(base, "/update.txt.sig", 1024)?;
    if !signed(&list, &signature) {
        return Err("the update list is not signed by this project: nothing was installed".into());
    }
    let listed = std::str::from_utf8(&list).ok().and_then(read).ok_or("the update list was not understood")?;
    Ok(newer(&listed.version, crate::VERSION).then_some(listed))
}

/// What came of looking for an update.
#[derive(Debug, PartialEq)]
pub enum Outcome {
    Current,
    /// This program file was replaced by the named version. The agent has to start again to run it.
    Replaced(String),
    /// The package manager was asked to install the named version; it restarts the agent itself.
    Packaged(String),
}

#[cfg(target_os = "linux")]
fn packaged(exe: &Path) -> bool {
    exe.starts_with("/usr/lib/garrett") && Path::new("/var/lib/dpkg/info/garrett.list").exists() && Path::new("/etc/apt/sources.list.d/garrett.list").exists()
        && Path::new("/run/systemd/system").exists() && ["/usr/bin/systemd-run", "/bin/systemd-run"].iter().any(|tool| Path::new(tool).exists())
}

/// Have apt install the newer package. It runs in a unit of its own: the package restarts this agent while it
/// installs, and that must not take the installer down with it.
#[cfg(target_os = "linux")]
fn by_package() -> Result<(), String> {
    let script = "apt-get update -qq -o Dir::Etc::sourcelist=/etc/apt/sources.list.d/garrett.list -o Dir::Etc::sourceparts=- -o APT::Get::List-Cleanup=0; \
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --only-upgrade -o DPkg::Lock::Timeout=300 -o Dpkg::Options::=--force-confold garrett";
    let unit = format!("garrett-update-{}", crate::agent::now() as u64);
    crate::tool::run(&["systemd-run", "--quiet", "--collect", "--unit", &unit, "/bin/sh", "-c", script], None, Duration::from_secs(30)).map(|_| ()).ok_or_else(|| "apt could not be started".to_string())
}

fn beside(exe: &Path, word: &str) -> PathBuf {
    let name = exe.file_name().map(|name| name.to_string_lossy().into_owned()).unwrap_or_else(|| "garrett".into());
    match name.strip_suffix(".exe") {
        Some(stem) => exe.with_file_name(format!("{stem}-{word}.exe")),
        None => exe.with_file_name(format!("{name}.{word}")),
    }
}

/// Fetch the listed program file for this machine, check it, and put it in place of `exe`.
fn replace(base: &str, listed: &Listed, exe: &Path) -> Result<(), String> {
    let name = file_name().ok_or("no program file is published for this kind of machine")?;
    let want = listed.files.iter().find(|(_, known)| known == name).map(|(sum, _)| sum.as_str()).ok_or("the update list does not name a program file for this machine")?;
    let data = crate::agent::fetch(base, &format!("/{name}"), 96 * 1024 * 1024)?;
    let have: String = Sha256::digest(&data).iter().map(|byte| format!("{byte:02x}")).collect();
    if have != want {
        return Err("the downloaded program file does not match the signed list: nothing was installed".into());
    }
    let fresh = beside(exe, "new");
    let _ = std::fs::remove_file(&fresh);
    std::fs::write(&fresh, &data).map_err(|error| format!("the new program file could not be written: {error}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&fresh, std::fs::Permissions::from_mode(0o755)).map_err(|error| error.to_string())?;
    }
    // It must run on this machine and be the version the list names, before it replaces anything.
    let said = crate::tool::run(&[&fresh.to_string_lossy(), "version"], None, Duration::from_secs(30)).unwrap_or_default();
    if said.trim() != format!("garrett {}", listed.version) {
        let _ = std::fs::remove_file(&fresh);
        return Err("the new program file did not run here: the installed one was kept".into());
    }
    #[cfg(not(windows))]
    std::fs::rename(&fresh, exe).map_err(|error| format!("the program file could not be replaced: {error}"))?;
    #[cfg(windows)]
    {
        // A running program's file cannot be written over here, but it can be moved aside.
        let old = beside(exe, "old");
        let _ = std::fs::remove_file(&old);
        std::fs::rename(exe, &old).map_err(|error| format!("the program file could not be moved aside: {error}"))?;
        if let Err(error) = std::fs::rename(&fresh, exe) {
            let _ = std::fs::rename(&old, exe);
            return Err(format!("the program file could not be replaced: {error}"));
        }
    }
    Ok(())
}

/// Look for a newer version and install it.
pub fn bring_current(base: &str) -> Result<Outcome, String> {
    let Some(listed) = check(base)? else { return Ok(Outcome::Current) };
    let exe = std::env::current_exe().map_err(|error| error.to_string())?;
    #[cfg(target_os = "linux")]
    if packaged(&exe) {
        by_package()?;
        return Ok(Outcome::Packaged(listed.version));
    }
    replace(base, &listed, &exe)?;
    Ok(Outcome::Replaced(listed.version))
}

/// True where the agent runs as the scheduled task its installer makes.
#[cfg(windows)]
pub fn as_task() -> bool {
    std::process::Command::new("schtasks.exe").args(["/Query", "/TN", "garrett"]).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).status().is_ok_and(|status| status.success())
}

/// Start the program file that is in place now, with the arguments this one was started with. Called as the last
/// thing a running agent does after it replaced itself. Returns only if that could not be done.
pub fn start_again(exe: &Path) {
    let arguments: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let error = std::process::Command::new(exe).args(&arguments).exec();
        eprintln!("garrett: the new version could not be started: {error}");
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const NO_WINDOW: u32 = 0x0800_0000;
        const NEW_GROUP: u32 = 0x0000_0200;
        // As the scheduled task: the task is started again a moment after this process has ended, so the new
        // agent runs under the task like the old one. Otherwise the new program is started directly.
        let started = if as_task() {
            std::process::Command::new("cmd.exe").args(["/c", "ping -n 4 127.0.0.1 >nul & schtasks /Run /TN garrett"]).creation_flags(NO_WINDOW | NEW_GROUP).spawn()
        } else {
            std::process::Command::new(exe).args(&arguments).creation_flags(NEW_GROUP).spawn()
        };
        if let Err(error) = started {
            eprintln!("garrett: the new version could not be started: {error}");
        }
    }
    #[cfg(not(any(unix, windows)))]
    let _ = (exe, arguments);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_official_site_is_an_address_the_downloader_takes() {
        assert_eq!(crate::agent::split_site(SOURCE), Ok(("https://gary23w.github.io".to_string(), "/sentinels".to_string())));
        assert_eq!(crate::agent::split_site("https://example.org/"), Ok(("https://example.org".to_string(), String::new())));
        assert_eq!(crate::agent::split_site("http://127.0.0.1:8766/a/b/"), Ok(("http://127.0.0.1:8766".to_string(), "/a/b".to_string())));
        assert!(crate::agent::split_site("http://example.org/x").is_err(), "plain http only to this machine itself");
        assert!(crate::agent::split_site("https://example.org/a/../b").is_err());
    }

    #[test]
    fn only_a_later_version_counts_as_newer() {
        assert!(newer("1.1.0", "1.0.0") && newer("1.0.10", "1.0.9") && newer("2.0", "1.9.9") && newer("1.0.0.1", "1.0.0"));
        assert!(!newer("1.0.0", "1.0.0") && !newer("1.0.0", "1.1.0") && !newer("0.9.9", "1.0.0"));
        assert!(!newer("latest", "1.0.0") && !newer("1.1.0-rc1", "1.0.0") && !newer("", "1.0.0") && !newer("9", "one"));
    }

    #[test]
    fn the_list_is_a_version_and_file_sums_and_nothing_else() {
        let sum = "a".repeat(64);
        let listed = read(&format!("garrett 1.2.3\n{sum}  garrett-linux-x86_64\n{sum}  garrett-windows.exe\n")).unwrap();
        assert_eq!(listed.version, "1.2.3");
        assert_eq!(listed.files.len(), 2);
        assert!(read(&format!("{sum}  garrett-linux-x86_64\n")).is_none(), "no version line");
        assert!(read("garrett one\n").is_none());
        assert!(read(&format!("garrett 1.2.3\n{sum}  ../../etc/passwd\n")).is_none(), "a name is never a path");
        assert!(read(&format!("garrett 1.2.3\nshort  garrett-macos\n")).is_none());
    }

    #[test]
    fn a_list_counts_only_with_this_projects_signature() {
        // Made once with the project's key for these exact bytes; any other bytes, or any other signature, fail.
        let list = b"garrett 0.0.0\n";
        assert!(!signed(list, b""));
        assert!(!signed(list, "00".repeat(64).as_bytes()));
        assert!(!signed(list, b"not hex at all"));
        let good = include_str!("../tests/fixtures/update-check.sig");
        assert!(signed(list, good.as_bytes()));
        assert!(!signed(b"garrett 9.9.9\n", good.as_bytes()), "a signature belongs to one list only");
    }
}
