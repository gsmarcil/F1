//! The system this agent was built for, behind one set of names: its sensor (`Live`, from `sensor`), its hands
//! (`RealHands`), how a look is prepared (`refresh_now`, `refresh_processes`, `background`) and how program starts reach the
//! responders (`Feeds`).

#[cfg(target_os = "linux")]
pub use crate::live::{background, refresh_now, refresh_processes, sensor, startup_signal, Feeds, Live, RealHands, SYSTEM};
#[cfg(target_os = "macos")]
pub use crate::mac::{background, refresh_now, refresh_processes, sensor, startup_signal, Feeds, Live, RealHands, SYSTEM};
#[cfg(windows)]
pub use crate::win::{background, refresh_now, refresh_processes, sensor, startup_signal, Feeds, Live, RealHands, SYSTEM};

/// The Windows folder, lower case with a closing backslash: what "a system program" is measured against.
pub fn system_root() -> String {
    let root = std::env::var("SystemRoot").ok().filter(|value| !value.is_empty()).unwrap_or_else(|| "C:\\Windows".into());
    format!("{}\\", root.to_lowercase().trim_end_matches('\\'))
}
