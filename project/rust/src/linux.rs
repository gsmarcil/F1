//! What is running on a Linux machine, read from /proc.
//!
//! The folder to read is a parameter, so the same code is proven against recorded /proc trees
//! (tests/fixtures/proc.jsonl) and then run against the real one.

use crate::parse::Proc;
use crate::score::{unix_writable, DIRECTORY_TOOLS, INTERPRETER_PREFIXES, SHELLS};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// A program that has just started: who it is, its command line, and the name of what started it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snap {
    pub proc: Proc,
    pub cmdline: String,
    pub parent: String,
    /// It runs as root, an ordinary user's program started it, and it never went through a program that grants
    /// root. Only the kernel's start feed can tell (see `feed`); everywhere else this is false.
    pub jumped: bool,
    /// It is a root shell that a system program which asks before it gives root turned into directly, without
    /// the step such a program always takes in between (Linux), so the program itself was tampered with.
    pub handed: bool,
}

fn base(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

fn lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// Whether a program that has just started is one worth reading up on at all: a shell, a script interpreter, a
/// directory tool, or anything started from a folder any program can write to. On a machine starting thousands
/// of programs a second nearly all of them are not, and they must cost next to nothing.
pub fn exec_worth(path: &str) -> bool {
    let name = base(path).to_lowercase();
    SHELLS.contains(&name.as_str()) || INTERPRETER_PREFIXES.iter().any(|prefix| name.starts_with(prefix)) || DIRECTORY_TOOLS.contains(&name.as_str()) || unix_writable().is_match(path)
}

#[cfg(target_os = "linux")]
fn has_capabilities(name: &std::ffi::CStr) -> bool {
    unsafe { libc::getxattr(name.as_ptr(), c"security.capability".as_ptr(), std::ptr::null_mut(), 0) > 0 }
}

#[cfg(all(unix, not(target_os = "linux")))]
fn has_capabilities(_name: &std::ffi::CStr) -> bool {
    false
}

/// Programs that hold root to do one small job, or that hand a root shell over only as a separate process: none
/// of them ever becomes a root shell itself.
const STAID: &[&str] = &["su", "passwd", "chsh", "chfn", "gpasswd", "chage", "expiry", "mount", "umount", "fusermount", "fusermount3", "unix_chkpwd", "ssh-keysign", "at", "ping", "ping6"];

pub struct LinuxSensor {
    pub proc: PathBuf,
    seen: Option<HashSet<u32>>,
}

impl LinuxSensor {
    pub fn new(proc: &Path) -> LinuxSensor {
        LinuxSensor { proc: proc.to_path_buf(), seen: None }
    }

    /// (name in brackets, the fields after it) from one process's `stat`.
    fn stat(&self, pid: u32) -> Option<(String, Vec<String>)> {
        let raw = lossy(&std::fs::read(self.proc.join(pid.to_string()).join("stat")).ok()?);
        let (open, close) = (raw.find('(')?, raw.rfind(')')?);
        if close < open {
            return None;
        }
        let rest = raw.get(close + 2..).unwrap_or("");
        Some((raw[open + 1..close].to_string(), rest.split_whitespace().map(str::to_string).collect()))
    }

    fn exe(&self, pid: u32) -> String {
        std::fs::read_link(self.proc.join(pid.to_string()).join("exe")).map(|path| path.to_string_lossy().into_owned()).unwrap_or_default()
    }

    fn pids(&self) -> Option<HashSet<u32>> {
        let mut found = HashSet::new();
        for entry in std::fs::read_dir(&self.proc).ok()? {
            let Ok(entry) = entry else { continue };
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if !name.is_empty() && name.chars().all(|c| c.is_ascii_digit()) {
                if let Ok(pid) = name.parse() {
                    found.insert(pid);
                }
            }
        }
        Some(found)
    }

    fn identity(&self, pid: u32) -> Option<Proc> {
        let (comm, fields) = self.stat(pid)?;
        let path = self.exe(pid);
        let ppid: u32 = fields.get(1)?.parse().ok()?;
        let started: u64 = fields.get(19)?.parse().ok()?;
        let name = if base(&path).is_empty() { comm } else { base(&path).to_string() };
        Some(Proc { pid, ppid, name, path, started })
    }

    /// Every running process, lowest id first. One that ends while being read is simply not listed.
    pub fn processes(&self) -> Vec<Proc> {
        let mut pids: Vec<u32> = self.pids().unwrap_or_default().into_iter().collect();
        pids.sort_unstable();
        pids.into_iter().filter_map(|pid| self.identity(pid)).collect()
    }

    fn cmdline(&self, pid: u32) -> Option<String> {
        let mut raw = std::fs::read(self.proc.join(pid.to_string()).join("cmdline")).ok()?;
        raw.truncate(4096);
        for byte in raw.iter_mut() {
            if *byte == 0 {
                *byte = b' ';
            }
        }
        Some(lossy(&raw))
    }

    /// One program that has just started. `None` when it is already gone.
    pub fn snapshot(&self, pid: u32) -> Option<Snap> {
        let proc = self.identity(pid)?;
        // A kernel thread has no program file: it is known by the name the kernel gives it.
        let parent = self.identity(proc.ppid).map(|above| above.name).unwrap_or_default();
        let cmdline = self.cmdline(pid)?.trim().to_string();
        Some(Snap { proc, cmdline, parent, jumped: false, handed: false })
    }

    /// (real, effective, saved, file-system) user of a process.
    fn users(&self, pid: u32) -> Option<[u32; 4]> {
        let raw = lossy(&std::fs::read(self.proc.join(pid.to_string()).join("status")).ok()?);
        let line = raw.lines().find(|line| line.starts_with("Uid:"))?;
        let found: Vec<u32> = line[4..].split_whitespace().filter_map(|part| part.parse().ok()).collect();
        (found.len() == 4).then(|| [found[0], found[1], found[2], found[3]])
    }

    /// The user a process runs as, read from who owns its folder here: one question, for a feed that asks it of
    /// every new process. `None` when it is gone.
    pub fn owner(&self, pid: u32) -> Option<u32> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            std::fs::metadata(self.proc.join(pid.to_string())).ok().map(|meta| meta.uid())
        }
        #[cfg(not(unix))]
        {
            self.users(pid).map(|found| found[1])
        }
    }

    /// Whether a program file hands root to whoever runs it: owned by root and marked set-user-id, or carrying
    /// capabilities. The file is looked up where the process itself sees it, so a container's own files are the
    /// ones read. `None` when it cannot be read.
    #[cfg(unix)]
    fn grants_root(&self, pid: u32, image: &Path) -> Option<bool> {
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::MetadataExt;
        let inside = self.proc.join(pid.to_string()).join("root").join(image.strip_prefix("/").ok()?);
        let meta = std::fs::metadata(&inside).ok()?;
        if meta.uid() == 0 && meta.mode() & 0o4000 != 0 {
            return Some(true);
        }
        let name = std::ffi::CString::new(inside.as_os_str().as_bytes()).ok()?;
        Some(has_capabilities(&name))
    }

    #[cfg(not(unix))]
    fn grants_root(&self, _pid: u32, _image: &Path) -> Option<bool> {
        None
    }

    /// True when this process runs as root, the process that started it belongs to an ordinary user, and none
    /// of the programs it has been since it was born (`images`, the newest last) grants root. That is what a
    /// kernel or service exploit leaves: root without `su`, `sudo` or any other program allowed to give it.
    /// With nothing known about its past, or a file that cannot be read, the answer is no.
    pub fn jumped(&self, proc: &Proc, images: &[PathBuf]) -> bool {
        if proc.ppid <= 2 || images.is_empty() {
            return false;
        }
        let (Some(own), Some(above)) = (self.users(proc.pid), self.users(proc.ppid)) else { return false };
        if own[1] != 0 || above.contains(&0) {
            return false;
        }
        images.iter().all(|image| self.grants_root(proc.pid, image) == Some(false))
    }

    /// Whether a program file contains these bytes, read where the process itself sees the file.
    fn mentions(&self, pid: u32, image: &Path, needle: &[u8]) -> bool {
        let Ok(inside) = image.strip_prefix("/") else { return false };
        let inside = self.proc.join(pid.to_string()).join("root").join(inside);
        if !std::fs::metadata(&inside).is_ok_and(|meta| meta.len() <= 4_194_304) {
            return false;
        }
        std::fs::read(&inside).is_ok_and(|body| body.windows(needle.len()).any(|part| part == needle))
    }

    /// True when this process is a root shell, the process that started it belongs to an ordinary user, and the
    /// program it was a moment ago is one that grants root only to do its own small job, or (`su`) only after
    /// asking and then by starting the shell as a separate process. Such a program turning straight into a root
    /// shell is what overwriting its code in memory looks like from outside.
    pub fn handed(&self, proc: &Proc, images: &[PathBuf]) -> bool {
        if proc.ppid <= 2 || images.len() < 2 || !SHELLS.contains(&proc.name.to_lowercase().as_str()) {
            return false;
        }
        let (Some(own), Some(above)) = (self.users(proc.pid), self.users(proc.ppid)) else { return false };
        if own[1] != 0 || above.contains(&0) {
            return false;
        }
        let before = &images[images.len() - 2];
        let name = base(&before.to_string_lossy()).to_string();
        if !STAID.contains(&name.as_str()) || self.grants_root(proc.pid, before) != Some(true) {
            return false;
        }
        // An `su` built without the sign-in library starts the shell in its own place, and that is its ordinary way.
        name != "su" || self.mentions(proc.pid, before, b"libpam")
    }

    /// Processes that appeared since the last call: one directory listing, then only the new ones are read.
    pub fn fresh(&mut self) -> Vec<Snap> {
        let Some(now) = self.pids() else { return Vec::new() };
        let mut new: Vec<u32> = match &self.seen {
            Some(before) => now.difference(before).copied().collect(),
            None => Vec::new(), // the first look: what is already running is not news
        };
        self.seen = Some(now);
        new.sort_unstable();
        new.into_iter().take(256).filter_map(|pid| self.snapshot(pid)).collect()
    }

    /// The command lines of up to sixteen processes, as they are, for those still running.
    pub fn command_lines(&self, pids: &[u32]) -> Vec<(u32, String)> {
        pids.iter().take(16).filter_map(|pid| self.cmdline(*pid).map(|line| (*pid, line))).collect()
    }
}
