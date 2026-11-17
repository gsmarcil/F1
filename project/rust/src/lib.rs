//! garrett: the Sentinel agent.
//!
//! What it decides is recorded as fixtures and replayed by the tests (`tests/parity.rs`), so a change that alters
//! a decision fails there. The pieces:
//!
//!   net, score     which addresses are the internet; the scorer, containment chains, automation marks
//!   parse          the system tools' output (ss, lsof, ps) as processes and connections
//!   linux          what is running on a Linux machine, read from /proc
//!   respond        freeze, release or end one process (Linux, macOS)
//!   feed, notify   the Linux kernel's process-start feed, its notices by file, the startup signal
//!   watch          the watcher: following programs, cases, freezing and ending, decisions, the fleet, blocking
//!   clean          quarantine, switching startup entries off, restore, the startup watch (Linux, macOS)
//!   clean_win      the same on Windows: startup folders, Run values, scheduled tasks, services
//!   web            the web server's access logs, container logs and web folders
//!   persist        where a reported program is set to start again
//!   live, mac, win the real machine on each system: its sensor, its hands, how program starts are noticed
//!   machine, tool  the three behind one set of names, and what they share
//!   agent, run     state, the service client, the service loop and the no-service loop

pub mod agent;
#[cfg(unix)]
pub mod clean;
#[cfg(windows)]
pub mod clean_win;
#[cfg(target_os = "linux")]
pub mod feed;
pub mod card;
pub mod devices;
pub mod hardware;
pub mod lan;
pub mod learn;
pub mod linux;
#[cfg(target_os = "linux")]
pub mod live;
#[cfg(target_os = "macos")]
pub mod mac;
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
pub mod machine;
pub mod net;
#[cfg(target_os = "linux")]
pub mod notify;
pub mod parse;
pub mod persist;
pub mod respond;
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
pub mod run;
pub mod score;
pub mod shield;
pub mod signin;
#[cfg(windows)]
pub mod startup_win;
pub mod tool;
pub mod update;
pub mod watch;
pub mod web;
#[cfg(windows)]
pub mod win;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
