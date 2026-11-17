//! Freeze, release or end one process. Freezing is reversible; ending is not.

/// Hold a process still: it keeps everything it has and does nothing more until released.
#[cfg(unix)]
pub fn suspend(pid: u32) -> bool {
    signal(pid, libc::SIGSTOP)
}

/// Let a held process continue exactly where it was.
#[cfg(unix)]
pub fn resume(pid: u32) -> bool {
    signal(pid, libc::SIGCONT)
}

/// End a process. It cannot refuse.
#[cfg(unix)]
pub fn kill(pid: u32) -> bool {
    signal(pid, libc::SIGKILL)
}

#[cfg(unix)]
fn signal(pid: u32, number: libc::c_int) -> bool {
    // Never the whole process group, never "every process": only one real process id.
    if pid <= 1 || pid > i32::MAX as u32 {
        return false;
    }
    unsafe { libc::kill(pid as libc::pid_t, number) == 0 }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;
    use std::process::Command;

    fn state(pid: u32) -> String {
        let out = Command::new("ps").args(["-o", "state=", "-p", &pid.to_string()]).output().expect("ps");
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    #[test]
    fn a_process_is_frozen_released_and_ended() {
        let mut child = Command::new("sleep").arg("30").spawn().expect("sleep");
        let pid = child.id();
        assert!(suspend(pid));
        std::thread::sleep(std::time::Duration::from_millis(100));
        assert!(state(pid).starts_with('T'), "not frozen: {}", state(pid));
        assert!(resume(pid));
        std::thread::sleep(std::time::Duration::from_millis(100));
        assert!(!state(pid).starts_with('T'), "still frozen: {}", state(pid));
        assert!(kill(pid));
        assert_eq!(child.wait().expect("wait").signal(), Some(libc::SIGKILL));
        assert!(!kill(pid), "a process that is gone cannot be ended again");
        assert!(!kill(0) && !kill(1) && !suspend(u32::MAX), "never the group, never init, never every process");
    }
}
