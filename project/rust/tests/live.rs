//! Checks that change the machine they run on. A plain `cargo test` never runs them: each is marked `ignore` and
//! is started by name, by hand or by the hosted checks, on a machine made for it.
//!
//!   GARRETT_LIVE_STATE   a folder for the cleaner's records and quarantine
//!   GARRETT_LIVE_FILES   the program files to clean up after, separated by `;`
//!
//!   GARRETT_LIVE_ADDRESS a public address to refuse and let through again (it must answer on port 80)
//!
//!   cargo test --release --test live -- --ignored live_clean
//!   cargo test --release --test live -- --ignored live_restore
//!   cargo test --release --test live -- --ignored live_block
//!   cargo test --release --test live -- --ignored live_jump     (Linux, as root, with capsh, python3 and cc)
//!   cargo test --release --test live -- --ignored live_system_shell   (Windows, with GARRETT_LIVE_PID)
//!   cargo test --release --test live -- --ignored live_card       (macOS, as root)

const KEY: &str = "0123456789abcdef0123456789abcdef";

fn state() -> std::path::PathBuf {
    std::path::PathBuf::from(std::env::var("GARRETT_LIVE_STATE").expect("GARRETT_LIVE_STATE"))
}

fn now() -> f64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs_f64()
}

/// Take the named program files away and switch off whatever would start them again.
#[test]
#[ignore]
fn live_clean() {
    let files: Vec<String> = std::env::var("GARRETT_LIVE_FILES").expect("GARRETT_LIVE_FILES").split(';').filter(|file| !file.is_empty()).map(str::to_string).collect();
    #[cfg(windows)]
    let steps = garrett::clean_win::Cleaner::new(&state()).clean(KEY, &files, &[], now());
    #[cfg(unix)]
    let steps = garrett::clean::Cleaner::new(if cfg!(target_os = "macos") { "macos" } else { "linux" }, &state(), None, false).clean(KEY, &files, &[], now() - 600.0, now());
    for step in &steps {
        println!("{} {}: {}", step["action"].as_str().unwrap_or(""), step["kind"].as_str().unwrap_or(""), step["where"].as_str().unwrap_or(""));
    }
    assert!(!steps.is_empty(), "nothing was cleaned");
}

/// Put everything back.
#[test]
#[ignore]
fn live_restore() {
    #[cfg(windows)]
    let (back, left) = garrett::clean_win::Cleaner::new(&state()).restore(KEY, now());
    #[cfg(unix)]
    let (back, left) = garrett::clean::Cleaner::new(if cfg!(target_os = "macos") { "macos" } else { "linux" }, &state(), None, false).restore(KEY, now());
    println!("{back} put back, {left} left");
    assert!(back > 0 && left == 0, "restore did not put everything back");
}

/// Fleet blocking, with the agent's own hands: an address that answers is refused, then let through again.
#[test]
#[ignore]
fn live_block() {
    use garrett::watch::Hands;
    let address = std::env::var("GARRETT_LIVE_ADDRESS").expect("GARRETT_LIVE_ADDRESS");
    let target: std::net::SocketAddr = format!("{address}:80").parse().expect("an address");
    let reach = || std::net::TcpStream::connect_timeout(&target, std::time::Duration::from_secs(6)).is_ok();
    let mut hands = garrett::machine::RealHands::default();
    let before = reach();
    let blocked = hands.block(&[address.clone()]);
    let during = reach();
    let cleared = hands.block(&[]);
    let after = reach();
    println!("before {before} | blocked {blocked:?} | during {during} | cleared {cleared:?} | after {after}");
    assert!(before, "the test address did not answer to begin with");
    assert!(blocked == Some(true) && !during && cleared == Some(true) && after, "fleet blocking did not behave as expected");
}

/// A process born as an ordinary user turns into a root shell without having been `su`, `sudo` or any other
/// program that grants root: the start feed says so. So it does when a stand-in for a tampered `su` turns straight
/// into a root shell. Going up through `sudo` is not remarked on.
#[cfg(target_os = "linux")]
#[test]
#[ignore]
fn live_jump() {
    use garrett::feed::ExecFeed;
    use std::time::{Duration, Instant};
    let feed = ExecFeed::open(std::path::Path::new("/proc")).expect("the start feed needs root");
    std::thread::sleep(Duration::from_millis(500));
    let shell = |line: &str| std::process::Command::new("sh").args(["-c", line]).status().map(|status| status.success()).unwrap_or(false);
    // (root that nothing granted, root handed over by a program that never does) among the starts of these seconds.
    let seen_within = |seconds: u64| {
        let (until, mut jumped, mut handed) = (Instant::now() + Duration::from_secs(seconds), false, false);
        while Instant::now() < until {
            if let Ok(snap) = feed.starts.recv_timeout(Duration::from_millis(200)) {
                jumped |= snap.jumped;
                handed |= snap.handed;
            }
        }
        (jumped, handed)
    };
    // The ordinary way up, where this machine lets the user who called `sudo` use it without a password.
    if let Ok(user) = std::env::var("SUDO_USER") {
        if user != "root" && shell(&format!("sudo -n -u {user} sudo -n true")) {
            assert!(shell(&format!("sudo -n -u {user} sh -c 'sudo -n sh -c \"sleep 0.3\"; true'")));
            assert_eq!(seen_within(2), (false, false), "root through sudo was taken for an escalation");
        }
    }
    // Root that nothing granted: a process of the user `nobody` that holds the right to change user, changes to
    // root and starts a shell. No program on its way grants root.
    let folder = std::path::Path::new("/usr/local/libexec/garrett-live");
    let _ = std::fs::remove_dir_all(folder);
    std::fs::create_dir_all(folder).unwrap();
    std::fs::write(folder.join("up.py"), "import os
os.setuid(0)
os.execv('/bin/sh', ['sh', '-c', 'sleep 3'])
").unwrap();
    assert!(shell("chmod 755 /usr/local/libexec/garrett-live && chmod 644 /usr/local/libexec/garrett-live/up.py"));
    let line = "capsh --caps='cap_setuid+eip cap_setpcap,cap_setgid+ep' --keep=1 --user=nobody --addamb=cap_setuid -- -c 'python3 /usr/local/libexec/garrett-live/up.py; true'";
    let child = std::process::Command::new("sh").args(["-c", line]).spawn().expect("capsh and python3 are needed");
    assert_eq!(seen_within(6), (true, false), "root that no program granted");
    let _ = child.wait_with_output();
    // A stand-in for a tampered `su`: a program of that name that grants root, is built with the sign-in library's
    // name in it as the real one is, and turns straight into a root shell, which the real one never does.
    std::fs::write(folder.join("su.c"), "#include <unistd.h>\nconst char *library = \"libpam.so.0\";\nint main(void) { if (library[0] == 0 || setuid(0)) return 1; execl(\"/bin/sh\", \"sh\", \"-c\", \"sleep 3\", (char *)0); return 1; }\n").unwrap();
    assert!(shell("cd /usr/local/libexec/garrett-live && cc -O0 -o su su.c && chown root:root su && chmod 4755 su && chmod 755 ."), "the stand-in could not be built");
    let child = std::process::Command::new("sh").args(["-c", "sudo -n -u nobody sh -c '/usr/local/libexec/garrett-live/su; true'"]).spawn().unwrap();
    let seen = seen_within(6);
    let _ = child.wait_with_output();
    let _ = std::fs::remove_dir_all(folder);
    assert_eq!(seen, (false, true), "root handed over by a program that never becomes a root shell");
}

/// GARRETT_LIVE_PID is a shell that runs as SYSTEM and was started by a program of an ordinary account (the hosted
/// check makes one). The agent's reading of it says so, and says nothing of a shell started the ordinary way.
#[cfg(windows)]
#[test]
#[ignore]
fn live_system_shell() {
    let pid: u32 = std::env::var("GARRETT_LIVE_PID").expect("GARRETT_LIVE_PID").parse().expect("a process id");
    let snap = garrett::win::snapshot(pid).expect("the stand-in is running");
    println!("{} started by {}: jumped {}", snap.proc.name, snap.parent, snap.jumped);
    assert!(snap.jumped, "a SYSTEM shell under a person's program was not noticed");
    let mut ordinary = std::process::Command::new("cmd.exe").args(["/c", "ping -n 4 127.0.0.1 > nul"]).spawn().unwrap();
    std::thread::sleep(std::time::Duration::from_millis(300));
    let own = garrett::win::snapshot(ordinary.id()).expect("the ordinary shell is running");
    let _ = ordinary.wait();
    assert!(!own.jumped, "an ordinary shell was taken for an escalation");
}

/// The network card this Mac sends out through can be opened for the first packets of arriving connection
/// attempts, the kernel takes the filter, and reading it for a few seconds ends cleanly when told to stop. Whatever
/// arrives in that time is a packet that opens a connection, or nothing is handed over at all.
#[cfg(target_os = "macos")]
#[test]
#[ignore]
fn live_card() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let card = garrett::lan::way_out_card().expect("this machine has a way out");
    println!("reading at {card}");
    static STOP: AtomicBool = AtomicBool::new(false);
    std::thread::spawn(|| {
        std::thread::sleep(std::time::Duration::from_secs(4));
        STOP.store(true, Ordering::SeqCst);
    });
    let (mut handed, mut openings) = (0u32, 0u32);
    garrett::card::listen(&STOP, &card, |packet| {
        handed += 1;
        openings += u32::from(garrett::lan::opening(packet).is_some());
    }).expect("the card could not be opened");
    println!("{handed} packet(s) handed over, {openings} of them the first of a connection attempt");
    assert_eq!(handed, openings, "something other than an opening packet came through the filter");
}
