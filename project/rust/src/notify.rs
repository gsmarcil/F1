//! Two more things the Linux kernel tells this agent as they happen. Both only listen: nothing waits on them.
//!
//! `ExecNotify`: every program start, by file (fanotify, notification only). The process-start feed in `feed.rs`
//! reports process numbers as the machine's first namespace sees them, so inside a container or WSL it cannot be
//! used; this one reports them as this agent sees them.
//!
//! `StartupSignal`: the instant a file in a startup place changes (inotify).

#![cfg(target_os = "linux")]

use crate::linux::{exec_worth, LinuxSensor, Snap};
use std::ffi::CString;
use std::path::{Path, PathBuf};
use std::sync::mpsc::Sender;

const FILESYSTEMS: &[&str] = &["ext4", "ext3", "ext2", "xfs", "btrfs", "overlay", "tmpfs", "zfs", "f2fs", "squashfs", "erofs", "9p", "fuseblk", "virtiofs"];
const FAN_OPEN_EXEC: u64 = 0x1000;
const FAN_MARK_ADD: libc::c_uint = 0x1;
const FAN_MARK_MOUNT: libc::c_uint = 0x10;
const FAN_MARK_FILESYSTEM: libc::c_uint = 0x100;

/// Ask for notices from every file system programs can be started from. Returns how many are covered.
fn mark(handle: libc::c_int, proc: &Path, seen: &mut Vec<String>) -> usize {
    let Ok(rows) = std::fs::read_to_string(proc.join("self/mountinfo")) else { return 0 };
    let mut covered = 0;
    for row in rows.lines() {
        let parts: Vec<&str> = row.split_whitespace().collect();
        let Some(dash) = parts.iter().position(|part| *part == "-") else { continue };
        let (Some(device), Some(point), Some(kind)) = (parts.get(2), parts.get(4), parts.get(dash + 1)) else { continue };
        if !FILESYSTEMS.contains(kind) {
            continue;
        }
        if seen.iter().any(|known| known == device) {
            covered += 1;
            continue;
        }
        let Ok(path) = CString::new(point.replace("\\040", " ")) else { continue };
        for scope in [FAN_MARK_FILESYSTEM, FAN_MARK_MOUNT] {
            // The whole file system; failing that, this mount of it.
            if unsafe { libc::fanotify_mark(handle, FAN_MARK_ADD | scope, FAN_OPEN_EXEC, libc::AT_FDCWD, path.as_ptr()) } == 0 {
                seen.push(device.to_string());
                covered += 1;
                break;
            }
        }
    }
    covered
}

/// Start listening for program starts by file, and send each one worth a look. Fails where it is not permitted.
pub fn exec_notify(proc: &Path, starts: Sender<Snap>) -> std::io::Result<()> {
    let handle = unsafe { libc::fanotify_init(libc::FAN_CLASS_NOTIF | libc::FAN_CLOEXEC, (libc::O_RDONLY | libc::O_LARGEFILE | libc::O_CLOEXEC) as libc::c_uint) };
    if handle < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut seen = Vec::new();
    if mark(handle, proc, &mut seen) == 0 {
        unsafe { libc::close(handle) };
        return Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "program-start notices are not available here"));
    }
    let proc: PathBuf = proc.to_path_buf();
    std::thread::Builder::new().name("garrett-notify".into()).spawn(move || {
        let (sensor, own) = (LinuxSensor::new(&proc), std::process::id() as i32);
        let mut data = [0u8; 8192];
        let mut marked = std::time::Instant::now();
        loop {
            let mut wait = libc::pollfd { fd: handle, events: libc::POLLIN, revents: 0 };
            let ready = unsafe { libc::poll(&mut wait, 1, 5000) };
            if marked.elapsed().as_secs() > 30 {
                marked = std::time::Instant::now();
                mark(handle, &proc, &mut seen); // file systems that appeared since: new containers, new mounts
            }
            if ready <= 0 {
                continue;
            }
            let got = unsafe { libc::read(handle, data.as_mut_ptr() as *mut libc::c_void, data.len()) };
            if got <= 0 {
                continue;
            }
            let (got, mut offset) = (got as usize, 0usize);
            // Each record: length (4 bytes), version, reserved, header length (2), mask (8), file handle (4), process id (4).
            while offset + 24 <= got {
                let length = u32::from_ne_bytes(data[offset..offset + 4].try_into().expect("four bytes")) as usize;
                let descriptor = i32::from_ne_bytes(data[offset + 16..offset + 20].try_into().expect("four bytes"));
                let pid = i32::from_ne_bytes(data[offset + 20..offset + 24].try_into().expect("four bytes"));
                offset += length.max(24);
                let mut file = String::new();
                if descriptor >= 0 {
                    file = std::fs::read_link(format!("/proc/self/fd/{descriptor}")).map(|path| path.to_string_lossy().into_owned()).unwrap_or_default();
                    unsafe { libc::close(descriptor) };
                }
                let name = file.rsplit('/').next().unwrap_or("").to_string();
                // The loader every program opens is not a program start of its own; most programs need no second look.
                if pid <= 0 || pid == own || name.is_empty() || name.starts_with("ld-") || !exec_worth(&file) {
                    continue;
                }
                // The notice arrives as the start begins: wait, at most 2 ms, until it has happened. The program
                // file is in place a moment before the command line is, so an empty command line means "not yet".
                let mut snap = None;
                for _ in 0..20 {
                    match std::fs::read_link(proc.join(pid.to_string()).join("exe")) {
                        Ok(image) if image.file_name().is_some_and(|base| base.to_string_lossy() == name) => {
                            snap = sensor.snapshot(pid as u32);
                            if snap.as_ref().is_none_or(|snap| !snap.cmdline.is_empty()) {
                                break;
                            }
                            std::thread::sleep(std::time::Duration::from_micros(100));
                        }
                        Ok(_) => std::thread::sleep(std::time::Duration::from_micros(100)),
                        Err(_) => break,
                    }
                }
                if let Some(snap) = snap {
                    if starts.send(snap).is_err() {
                        unsafe { libc::close(handle) };
                        return;
                    }
                }
            }
        }
    })?;
    Ok(())
}

/// Send a note the instant a file in one of these folders is written, moved in or created. Returns how many
/// folders are being watched.
pub fn startup_signal(folders: &[PathBuf], changed: Sender<()>) -> std::io::Result<usize> {
    let handle = unsafe { libc::inotify_init1(libc::IN_CLOEXEC) };
    if handle < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut watching = 0;
    for folder in folders {
        let Ok(path) = CString::new(folder.to_string_lossy().as_bytes()) else { continue };
        if folder.is_dir() && unsafe { libc::inotify_add_watch(handle, path.as_ptr(), libc::IN_CLOSE_WRITE | libc::IN_MOVED_TO | libc::IN_CREATE) } >= 0 {
            watching += 1;
        }
    }
    std::thread::Builder::new().name("garrett-startup".into()).spawn(move || {
        let mut data = [0u8; 8192];
        loop {
            if unsafe { libc::read(handle, data.as_mut_ptr() as *mut libc::c_void, data.len()) } <= 0 || changed.send(()).is_err() {
                unsafe { libc::close(handle) };
                return;
            }
        }
    })?;
    Ok(watching)
}
