//! What is plugged in: keyboards.
//!
//! A device the size of a memory stick can say it is a keyboard and then type by itself, faster than anyone could:
//! it opens a command window and enters what its owner prepared. The system trusts a keyboard, so nothing stops it.
//! What gives it away is the order of things: a keyboard this machine has never seen appears, and seconds later a
//! command window opens. The keyboards are read here; the watcher joins the two (`keyboard_injection`).
//!
//! Only the names the system gives the devices are read. No key that is pressed is ever read.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

pub const FILE: &str = "sentinel-keyboards.json";

/// The USB keyboards of a Linux machine, read from the folder its files start at: each as maker:model:serial.
pub fn keyboards_linux(root: &Path) -> Option<BTreeSet<String>> {
    let folder = root.join("sys/bus/usb/devices");
    let read = |path: PathBuf| std::fs::read_to_string(path).map(|found| found.trim().to_lowercase()).unwrap_or_default();
    let mut found = BTreeSet::new();
    for entry in std::fs::read_dir(&folder).ok()?.flatten().take(1024) {
        let name = entry.file_name().to_string_lossy().into_owned();
        // An entry with a colon is one function of a device: class 03 with protocol 01 is a keyboard.
        let Some((device, _)) = name.split_once(':') else { continue };
        if read(entry.path().join("bInterfaceClass")) == "03" && read(entry.path().join("bInterfaceProtocol")) == "01" {
            let device = folder.join(device);
            let label: String = format!("{}:{}:{}", read(device.join("idVendor")), read(device.join("idProduct")), read(device.join("serial"))).chars().filter(|letter| !letter.is_control()).take(120).collect();
            found.insert(label);
        }
    }
    Some(found)
}

#[cfg(target_os = "linux")]
pub fn keyboards() -> Option<BTreeSet<String>> {
    keyboards_linux(Path::new("/"))
}

/// On Windows the system keeps a record of every keyboard that was ever plugged in: one that is new to the record
/// is one this machine has never seen. Only USB devices are counted.
#[cfg(windows)]
pub fn keyboards() -> Option<BTreeSet<String>> {
    use crate::startup_win::{machine_subkeys, machine_text};
    let base = "SYSTEM\\CurrentControlSet\\Enum\\HID";
    let mut found = BTreeSet::new();
    for device in machine_subkeys(base)?.into_iter().filter(|name| name.to_uppercase().starts_with("VID_")).take(512) {
        for instance in machine_subkeys(&format!("{base}\\{device}")).unwrap_or_default().into_iter().take(16) {
            if machine_text(&format!("{base}\\{device}\\{instance}"), "ClassGUID").is_some_and(|class| class.eq_ignore_ascii_case("{4d36e96b-e325-11ce-bfc1-08002be10318}")) {
                found.insert(format!("{device}\\{instance}").to_lowercase().chars().take(160).collect());
            }
        }
    }
    Some(found)
}

#[cfg(not(any(windows, target_os = "linux")))]
pub fn keyboards() -> Option<BTreeSet<String>> {
    None
}

/// Remembers every keyboard this machine has had, between runs, and says when one arrives that it never had.
pub struct KeyboardWatch {
    path: PathBuf,
    known: Option<BTreeSet<String>>,
}

impl KeyboardWatch {
    pub fn new(directory: &Path) -> KeyboardWatch {
        let path = directory.join(FILE);
        let known = std::fs::read(&path).ok().and_then(|raw| serde_json::from_slice::<BTreeSet<String>>(&raw).ok());
        KeyboardWatch { path, known }
    }

    /// Take a reading: how many keyboards are there now that this machine never had. The first reading is the
    /// starting point. A keyboard that is unplugged stays known: plugging it in again is not news.
    pub fn take(&mut self, present: &BTreeSet<String>) -> usize {
        let Some(known) = self.known.as_mut() else {
            self.known = Some(present.clone());
            self.keep();
            return 0;
        };
        let new: Vec<String> = present.difference(known).cloned().collect();
        if new.is_empty() {
            return 0;
        }
        known.extend(new.iter().cloned());
        while known.len() > 2000 {
            known.pop_first();
        }
        self.keep();
        new.len()
    }

    fn keep(&self) {
        let temporary = self.path.with_extension("tmp");
        if std::fs::write(&temporary, serde_json::to_string(&self.known).unwrap_or_default()).is_ok() {
            let _ = std::fs::rename(&temporary, &self.path);
        }
    }
}
