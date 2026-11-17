//! Below the operating system: the firmware, what it starts, and what is loaded into the kernel.
//!
//! An agent that runs as a program cannot stand inside the firmware, and this one never writes to it. What it can
//! do is read, from the system, the things the firmware and the hardware say about themselves, remember them, and
//! say so when one changes in a way an update does not explain:
//!
//!   - Secure Boot (on a Mac, System Integrity Protection) was on and is now off;
//!   - the firmware was given a new boot entry, or one was changed: where a boot kit puts itself;
//!   - the firmware is older than it was: an old, exploitable one was put back;
//!   - the security chip's measurement of the firmware changed while the firmware says it is the same version:
//!     its code was altered without an update;
//!   - the code the machine starts from changed: the boot sector of a disk, the space behind it where GRUB keeps
//!     its core on a BIOS machine, or a boot loader file on the firmware's partition, and no boot loader update
//!     was installed that would explain it;
//!   - a kernel module is loaded that is not among the modules installed for the running kernel;
//!   - Windows was restarted with its driver signature checks off.
//!
//! Everything here only reads. The first reading is the starting point, and nothing is ever reported from it.

use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// What this machine says about itself below the system, by name.
pub type Facts = BTreeMap<String, String>;

pub const FILE: &str = "sentinel-hardware.json";

/// One thing that changed: the signal, its points, what it is about, and the sentence said about it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Change {
    pub signal: &'static str,
    pub points: i64,
    pub subject: String,
    pub evidence: String,
}

fn mark(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().take(8).map(|byte| format!("{byte:02x}")).collect()
}

fn text(path: &Path) -> Option<String> {
    let found = std::fs::read_to_string(path).ok()?;
    let found: String = found.trim().chars().filter(|letter| !letter.is_control()).take(200).collect();
    (!found.is_empty()).then_some(found)
}

/// A date the firmware gives (month/day/year, or year-month-day) as one number, year first.
pub fn day_number(date: &str) -> Option<u32> {
    let parts: Vec<u32> = date.split(['/', '-', '.']).filter_map(|part| part.trim().parse().ok()).collect();
    let (year, month, day) = match parts.as_slice() {
        [month, day, year] if *year > 1900 => (*year, *month, *day),
        [year, month, day] if *year > 1900 => (*year, *month, *day),
        _ => return None,
    };
    ((1..=12).contains(&month) && (1..=31).contains(&day) && year < 2200).then_some(year * 10000 + month * 100 + day)
}

const GLOBAL: &str = "8be4df61-93ca-11d2-aa0d-00e098032b8c";

/// What one firmware boot entry is called, and a mark of everything it says.
fn boot_entry(data: &[u8]) -> Option<String> {
    // Four bytes of the variable's own attributes, then the entry: attributes, the length of its path, its name
    // in sixteen-bit letters up to a zero, and the path.
    let entry = data.get(4..)?;
    let name: Vec<u16> = entry.get(6..)?.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).take_while(|unit| *unit != 0).take(80).collect();
    let name: String = String::from_utf16_lossy(&name).chars().filter(|letter| !letter.is_control()).collect();
    Some(format!("{name}|{}", mark(entry)))
}

/// The start of a disk: a mark of the boot code in its first sector, and (on a disk laid out the old way) of the
/// space between that sector and the first partition, where GRUB keeps its core on a BIOS machine. The disk's
/// own number and its table of partitions are left out, so repartitioning is not taken for a change of code.
fn disk_start(name: &str, data: &[u8], facts: &mut Facts) {
    if data.len() < 1024 || data[510..512] != [0x55, 0xaa] {
        return; // not a disk anything starts from
    }
    facts.insert(format!("boot_sector:{name}"), mark(&data[..440]));
    if &data[512..520] == b"EFI PART" {
        return; // the new layout keeps its table of partitions there
    }
    let first = (0..4).map(|slot| 446 + 16 * slot).filter(|at| data[at + 4] != 0)
        .map(|at| u32::from_le_bytes([data[at + 8], data[at + 9], data[at + 10], data[at + 11]]) as usize).filter(|start| *start > 1).min().unwrap_or(2048);
    let end = (first.min(2048) * 512).min(data.len());
    if end > 512 {
        facts.insert(format!("boot_gap:{name}"), mark(&data[512..end]));
    }
}

fn first_megabyte(path: &Path) -> Option<Vec<u8>> {
    use std::io::Read;
    let mut data = vec![0u8; 1_048_576];
    let mut file = std::fs::File::open(path).ok()?;
    let mut filled = 0;
    while filled < data.len() {
        match file.read(&mut data[filled..]) {
            Ok(0) | Err(_) => break,
            Ok(count) => filled += count,
        }
    }
    data.truncate(filled - filled % 512);
    Some(data)
}

/// The boot loader files under a folder of the firmware's partition: one fact for each, named by where it is.
fn loader_files(folder: &Path, prefix: &str, depth: usize, facts: &mut Facts) {
    let mut entries: Vec<PathBuf> = std::fs::read_dir(folder).map(|entries| entries.flatten().map(|entry| entry.path()).collect()).unwrap_or_default();
    entries.sort();
    for entry in entries.into_iter().take(200) {
        let name = entry.file_name().map(|name| name.to_string_lossy().to_lowercase()).unwrap_or_default();
        if entry.is_dir() {
            if depth > 0 {
                loader_files(&entry, &format!("{prefix}/{name}"), depth - 1, facts);
            }
        } else if (name.ends_with(".efi") || name == "core.img" || name == "boot.img") && facts.keys().filter(|key| key.starts_with("boot_file:")).count() < 64 {
            if let Some(body) = std::fs::metadata(&entry).ok().filter(|meta| meta.len() <= 67_108_864).and_then(|_| std::fs::read(&entry).ok()) {
                facts.insert(format!("boot_file:{prefix}/{name}"), mark(&body));
            }
        }
    }
}

/// When a boot loader was last installed or updated by the system's own software, as far as its records say.
fn loader_update_stamp(root: &Path) -> Option<String> {
    use std::time::UNIX_EPOCH;
    let seconds = |path: &Path| std::fs::metadata(path).and_then(|meta| meta.modified()).ok().and_then(|at| at.duration_since(UNIX_EPOCH).ok()).map(|at| at.as_secs());
    let mut newest: Option<u64> = None;
    // Debian and its family keep one list for each package: only the boot loader's own packages count.
    if let Ok(entries) = std::fs::read_dir(root.join("var/lib/dpkg/info")) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.ends_with(".list") && ["grub", "shim", "systemd-boot", "fwupd", "refind"].iter().any(|package| name.starts_with(package)) {
                newest = newest.max(seconds(&entry.path()));
            }
        }
    }
    // The others keep one record of everything installed.
    for record in ["var/lib/rpm/rpmdb.sqlite", "var/lib/rpm/Packages", "usr/lib/sysimage/rpm/rpmdb.sqlite", "var/lib/pacman/local", "lib/apk/db/installed", "var/db/pkg/local.sqlite"] {
        newest = newest.max(seconds(&root.join(record)));
    }
    newest.map(|at| at.to_string())
}

/// A Linux machine, read from the folder its files start at.
pub fn read_linux(root: &Path) -> Facts {
    read_linux_part(root, true)
}

/// The same; `disks` says whether the disks and the boot loader's files are read too. They are read once an hour,
/// so a disk that is asleep is not woken every few minutes; everything else is read each time.
pub fn read_linux_part(root: &Path, disks: bool) -> Facts {
    let mut facts = Facts::new();
    if disks {
        boot_code_linux(root, &mut facts);
    }
    below_linux(root, &mut facts);
    facts
}

/// What the machine starts from: the first megabyte of each fixed disk, and the boot loader's files.
fn boot_code_linux(root: &Path, facts: &mut Facts) {
    let mut disks: Vec<String> = std::fs::read_dir(root.join("sys/block")).map(|entries| entries.flatten().map(|entry| entry.file_name().to_string_lossy().into_owned()).collect()).unwrap_or_default();
    disks.sort();
    for disk in disks.iter().filter(|name| !["loop", "ram", "zram", "dm-", "md", "sr", "nbd", "fd"].iter().any(|kind| name.starts_with(kind))).take(8) {
        if text(&root.join("sys/block").join(disk).join("removable")).as_deref() == Some("0") {
            if let Some(data) = first_megabyte(&root.join("dev").join(disk)) {
                disk_start(disk, &data, facts);
            }
        }
    }
    for (parent, folder, prefix) in [("boot/efi", "EFI", "efi"), ("efi", "EFI", "efi"), ("boot", "EFI", "efi"), ("boot/grub", "i386-pc", "grub"), ("boot/grub2", "i386-pc", "grub")] {
        // The folder must carry exactly this name: where names differ only by their capitals, one place is not read twice.
        let parent = root.join(parent);
        if std::fs::read_dir(&parent).is_ok_and(|mut entries| entries.any(|entry| entry.is_ok_and(|entry| entry.file_name() == folder))) {
            loader_files(&parent.join(folder), prefix, 3, facts);
        }
    }
    if let Some(stamp) = loader_update_stamp(root) {
        facts.insert("loader_updates".into(), stamp);
    }
}

fn below_linux(root: &Path, facts: &mut Facts) {
    let variables = root.join("sys/firmware/efi/efivars");
    if variables.is_dir() {
        if let Ok(data) = std::fs::read(variables.join(format!("SecureBoot-{GLOBAL}"))) {
            facts.insert("boot_protection".into(), if data.get(4) == Some(&1) { "on" } else { "off" }.into());
        }
        let mut names: Vec<String> = std::fs::read_dir(&variables).map(|entries| entries.flatten().map(|entry| entry.file_name().to_string_lossy().into_owned()).collect()).unwrap_or_default();
        names.sort();
        for name in names.iter().filter(|name| name.len() == 9 + GLOBAL.len() && name.starts_with("Boot") && name.ends_with(GLOBAL) && name[4..8].bytes().all(|byte| byte.is_ascii_hexdigit())).take(64) {
            if let Some(entry) = std::fs::read(variables.join(name)).ok().and_then(|data| boot_entry(&data)) {
                facts.insert(format!("entry:{}", &name[..8]), entry);
            }
        }
    }
    let identity = root.join("sys/class/dmi/id");
    let firmware: Vec<String> = ["bios_vendor", "bios_version"].iter().filter_map(|name| text(&identity.join(name))).collect();
    if !firmware.is_empty() {
        facts.insert("firmware".into(), firmware.join(" "));
    }
    if let Some(date) = text(&identity.join("bios_date")) {
        facts.insert("firmware_date".into(), date);
    }
    if let Some(measure) = text(&root.join("sys/class/tpm/tpm0/pcr-sha256/0")) {
        facts.insert("measure0".into(), measure.to_lowercase());
    }
    // Kernel modules that are loaded but are not among those installed for the running kernel.
    if let (Some(release), Ok(loaded)) = (text(&root.join("proc/sys/kernel/osrelease")), std::fs::read_to_string(root.join("proc/modules"))) {
        let folder = root.join("lib/modules").join(&release);
        if let Ok(installed) = std::fs::read_to_string(folder.join("modules.dep")) {
            let plain = |name: &str| name.split('.').next().unwrap_or("").replace('-', "_");
            let file_name = |line: &str| line.split(':').next().unwrap_or("").rsplit('/').next().map(plain).unwrap_or_default();
            let mut known: std::collections::BTreeSet<String> = installed.lines().map(file_name).collect();
            known.extend(std::fs::read_to_string(folder.join("modules.builtin")).unwrap_or_default().lines().map(file_name));
            let mut loose: Vec<String> = loaded.lines().filter_map(|line| line.split_whitespace().next()).map(|name| name.replace('-', "_"))
                .filter(|name| !known.contains(name) && name.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')).take(40).collect();
            loose.sort();
            facts.insert("loose_modules".into(), loose.join(","));
        }
    }
    // Told to the owner, never judged.
    if let Some(lockdown) = text(&root.join("sys/kernel/security/lockdown")) {
        facts.insert("kernel_lockdown".into(), lockdown.split('[').nth(1).and_then(|rest| rest.split(']').next()).unwrap_or("").to_string());
    }
    facts.insert("security_chip".into(), if root.join("sys/class/tpm/tpm0").exists() { "present" } else { "none found" }.into());
    facts.insert("memory_guard".into(), if std::fs::read_dir(root.join("sys/class/iommu")).is_ok_and(|mut entries| entries.next().is_some()) { "on" } else { "off or not present" }.into());
}

#[cfg(windows)]
mod chip {
    use std::ffi::c_void;

    #[repr(C)]
    struct Params {
        version: u32,
        flags: u32,
    }

    #[link(name = "tbs")]
    extern "system" {
        fn Tbsi_Context_Create(params: *const Params, context: *mut *mut c_void) -> u32;
        fn Tbsip_Submit_Command(context: *mut c_void, locality: u32, priority: u32, command: *const u8, length: u32, answer: *mut u8, answered: *mut u32) -> u32;
        fn Tbsip_Context_Close(context: *mut c_void) -> u32;
    }

    /// The security chip's measurement of the firmware (register 0, SHA-256), asked through Windows. Read only.
    pub fn measure0() -> Option<String> {
        let params = Params { version: 2, flags: 4 }; // a version 2.0 chip
        let mut context: *mut c_void = std::ptr::null_mut();
        if unsafe { Tbsi_Context_Create(&params, &mut context) } != 0 || context.is_null() {
            return None;
        }
        // TPM2_PCR_Read: no sessions, one selection, SHA-256, three bytes of register marks with register 0 set.
        let command: [u8; 20] = [0x80, 0x01, 0, 0, 0, 20, 0, 0, 0x01, 0x7e, 0, 0, 0, 1, 0, 0x0b, 3, 1, 0, 0];
        let mut answer = [0u8; 128];
        let mut answered = answer.len() as u32;
        let code = unsafe { Tbsip_Submit_Command(context, 0, 200, command.as_ptr(), command.len() as u32, answer.as_mut_ptr(), &mut answered) };
        unsafe { Tbsip_Context_Close(context) };
        // The answer: ten bytes of header, the update counter, the selection it read, then one digest.
        if code != 0 || answered < 62 || answer[6..10] != [0, 0, 0, 0] || answer[24..28] != [0, 0, 0, 1] || answer[28..30] != [0, 32] {
            return None;
        }
        Some(answer[30..62].iter().map(|byte| format!("{byte:02x}")).collect())
    }
}

/// The partitions the firmware's boot entries start files from, as `bcdedit /enum firmware` names them.
pub fn firmware_partitions(listing: &str) -> Vec<String> {
    let mut found: Vec<String> = listing.split_whitespace().filter_map(|word| word.strip_prefix("partition=")).filter(|device| device.starts_with("\\Device\\HarddiskVolume") && device[22..].bytes().all(|byte| byte.is_ascii_digit()))
        .map(str::to_string).collect();
    found.sort();
    found.dedup();
    found
}

/// The firmware's boot entries as `bcdedit /enum firmware` lists them: each block's identifier, and the file on
/// the firmware's partition it starts. The words around them change with the language; these do not.
pub fn firmware_entries(listing: &str) -> Vec<(String, String)> {
    let mut found = Vec::new();
    for block in listing.replace('\r', "").split("\n\n") {
        let identifier = block.lines().filter_map(|line| line.split_whitespace().last()).find(|word| word.starts_with('{') && word.ends_with('}'));
        let file = block.lines().filter_map(|line| line.to_lowercase().find("\\efi\\").map(|at| line[at..].trim().to_string())).next();
        if let (Some(identifier), Some(file)) = (identifier, file) {
            found.push((identifier.to_lowercase(), file.chars().take(160).collect()));
        }
    }
    found
}

#[cfg(windows)]
pub fn read(disks: bool) -> Facts {
    use crate::startup_win::{machine_number, machine_text};
    let mut facts = Facts::new();
    if let Some(state) = machine_number("SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State", "UEFISecureBootEnabled") {
        facts.insert("boot_protection".into(), if state == 1 { "on" } else { "off" }.into());
    }
    let identity = "HARDWARE\\DESCRIPTION\\System\\BIOS";
    let firmware: Vec<String> = ["BIOSVendor", "BIOSVersion"].iter().filter_map(|name| machine_text(identity, name)).collect();
    if !firmware.is_empty() {
        facts.insert("firmware".into(), firmware.join(" "));
    }
    if let Some(date) = machine_text(identity, "BIOSReleaseDate") {
        facts.insert("firmware_date".into(), date);
    }
    if let Some(options) = machine_text("SYSTEM\\CurrentControlSet\\Control", "SystemStartOptions") {
        let low = options.to_lowercase();
        facts.insert("driver_checks".into(), if low.contains("testsigning") || low.contains("nointegritychecks") { "off" } else { "on" }.into());
    }
    match chip::measure0() {
        Some(measure) => {
            facts.insert("measure0".into(), measure);
            facts.insert("security_chip".into(), "present".into());
        }
        None => {
            facts.insert("security_chip".into(), "none found".into());
        }
    }
    if crate::win::privileged() {
        if let Some(listing) = crate::tool::run(&["bcdedit.exe", "/enum", "firmware"], None, std::time::Duration::from_secs(20)) {
            for (identifier, file) in firmware_entries(&listing).into_iter().take(64) {
                facts.insert(format!("entry:{identifier}"), file);
            }
            for device in firmware_partitions(&listing).into_iter().take(if disks { 4 } else { 0 }) {
                loader_files(Path::new(&format!("\\\\?\\GLOBALROOT{device}\\EFI")), "efi", 3, &mut facts);
            }
        }
        for number in 0..(if disks { 4 } else { 0 }) {
            if let Some(data) = first_megabyte(Path::new(&format!("\\\\.\\PhysicalDrive{number}"))) {
                disk_start(&format!("drive{number}"), &data, &mut facts);
            }
        }
        // Windows changes its own boot files with its updates: the update number says when one was installed.
        let version = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
        if let (Some(build), Some(update)) = (machine_text(version, "CurrentBuildNumber"), machine_number(version, "UBR")) {
            facts.insert("loader_updates".into(), format!("{build}.{update}"));
        }
    }
    facts
}

#[cfg(target_os = "macos")]
pub fn read(_disks: bool) -> Facts {
    let mut facts = Facts::new();
    let run = |arguments: &[&str]| crate::tool::run(arguments, None, std::time::Duration::from_secs(30)).unwrap_or_default();
    let protection = run(&["/usr/bin/csrutil", "status"]).to_lowercase();
    if protection.contains("status: enabled") {
        facts.insert("boot_protection".into(), "on".into());
    } else if protection.contains("status: disabled") {
        facts.insert("boot_protection".into(), "off".into());
    }
    let about = run(&["/usr/sbin/system_profiler", "SPHardwareDataType"]);
    if let Some(version) = about.lines().find_map(|line| line.trim().strip_prefix("System Firmware Version:").or_else(|| line.trim().strip_prefix("Boot ROM Version:"))) {
        facts.insert("firmware".into(), version.trim().chars().take(120).collect());
    }
    facts
}

#[cfg(target_os = "linux")]
pub fn read(disks: bool) -> Facts {
    read_linux_part(Path::new("/"), disks)
}

#[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
pub fn read(_disks: bool) -> Facts {
    Facts::new()
}

/// For this long after a boot loader update, what the update goes on to change at the next start is its doing.
pub const UPDATE_SECONDS: f64 = 86400.0;

/// What changed between two readings that an update does not explain. `updated` is when a boot loader update was
/// last seen to have been installed (0 for never); `at` is now.
pub fn changes(before: &Facts, now: &Facts, updated: f64, at: f64) -> Vec<Change> {
    let mut found = Vec::new();
    let was = |name: &str| before.get(name).map(String::as_str).unwrap_or("");
    let is = |name: &str| now.get(name).map(String::as_str).unwrap_or("");
    // A boot loader update rewrites the loader's files, sometimes the boot sector, and the firmware's own entries.
    let by_update = (!was("loader_updates").is_empty() && was("loader_updates") != is("loader_updates")) || (updated > 0.0 && at - updated < UPDATE_SECONDS);
    if !by_update {
        let had_files = before.keys().any(|name| name.starts_with("boot_file:"));
        for (name, value) in now.iter().filter(|(name, _)| name.starts_with("boot_sector:") || name.starts_with("boot_gap:") || name.starts_with("boot_file:")) {
            let (kind, place) = name.split_once(':').unwrap_or((name, ""));
            let changed = match before.get(name) {
                Some(old) => old != value,
                None => kind == "boot_file" && had_files, // a loader file that was not there
            };
            if !changed {
                continue;
            }
            let what = match kind {
                "boot_sector" => format!("the boot sector of {place}"),
                "boot_gap" => format!("the space behind the boot sector of {place}, where a boot loader keeps its core"),
                _ => format!("the boot loader file {place}"),
            };
            found.push(Change { signal: "boot_code_changed", points: 6, subject: what.chars().take(80).collect(),
                evidence: format!("The code this machine starts from changed ({what}), and no boot loader update was installed that would explain it.") });
            if found.len() >= 4 {
                break;
            }
        }
    }
    if was("boot_protection") == "on" && is("boot_protection") == "off" {
        found.push(Change { signal: "boot_protection_off", points: 6, subject: "boot protection".into(),
            evidence: "Secure Boot (on a Mac, System Integrity Protection) was on when this agent last looked and is now off.".into() });
    }
    if !by_update && before.keys().any(|name| name.starts_with("entry:")) {
        for (name, entry) in now.iter().filter(|(name, _)| name.starts_with("entry:")) {
            let said = entry.split('|').next().unwrap_or("");
            let low = entry.to_lowercase();
            if before.get(name) == Some(entry) || low.contains("firmware-updater") || low.contains("fwupd") {
                continue; // unchanged, or the entry a firmware update makes for itself
            }
            let what = if before.contains_key(name) { "changed" } else { "added" };
            found.push(Change { signal: "boot_entry_added", points: 5, subject: format!("boot entry {}", &name[6..]),
                evidence: format!("The firmware's list of what to start was {what}: {said}. A boot kit puts itself there.") });
            if found.len() >= 6 {
                break;
            }
        }
    }
    if let (Some(old), Some(new)) = (day_number(was("firmware_date")), day_number(is("firmware_date"))) {
        if new < old {
            found.push(Change { signal: "firmware_downgraded", points: 5, subject: "firmware".into(),
                evidence: format!("The firmware is older than it was: dated {} before, {} now. An old one with known holes may have been put back.", was("firmware_date"), is("firmware_date")) });
        }
    }
    if !was("measure0").is_empty() && !is("measure0").is_empty() && was("measure0") != is("measure0") && !is("firmware").is_empty() && was("firmware") == is("firmware") && was("firmware_date") == is("firmware_date") {
        found.push(Change { signal: "firmware_changed_unannounced", points: 6, subject: "firmware code".into(),
            evidence: "The security chip's measurement of the firmware changed, and the firmware still gives the same version and date: its code was altered without an update.".into() });
    }
    if before.contains_key("loose_modules") {
        let known: std::collections::BTreeSet<&str> = was("loose_modules").split(',').collect();
        for name in is("loose_modules").split(',').filter(|name| !name.is_empty() && !known.contains(name)).take(3) {
            found.push(Change { signal: "kernel_module_loose", points: 5, subject: format!("kernel module {name}"),
                evidence: format!("A kernel module named {name} was loaded that is not among the modules installed for the running kernel: how a root kit is put in.") });
        }
    }
    if was("driver_checks") == "on" && is("driver_checks") == "off" {
        found.push(Change { signal: "driver_checks_off", points: 6, subject: "driver checks".into(),
            evidence: "Windows was restarted with its driver signature checks off: any driver can now be loaded into the kernel.".into() });
    }
    found
}

/// Remembers the last reading between runs and says what changed since.
pub struct HardwareWatch {
    path: PathBuf,
    known: Option<Facts>,
}

impl HardwareWatch {
    pub fn new(directory: &Path) -> HardwareWatch {
        let path = directory.join(FILE);
        let known = std::fs::read(&path).ok().and_then(|raw| serde_json::from_slice::<Facts>(&raw).ok());
        HardwareWatch { path, known }
    }

    /// Take a new reading at this moment. A fact that could not be read this time keeps the value it had.
    pub fn take(&mut self, facts: Facts, at: f64) -> Vec<Change> {
        let updated = self.known.as_ref().and_then(|before| before.get("loader_update_seen")).and_then(|seen| seen.parse::<f64>().ok()).unwrap_or(0.0);
        let found = self.known.as_ref().map(|before| changes(before, &facts, updated, at)).unwrap_or_default();
        let mut kept = self.known.clone().unwrap_or_default();
        if kept.get("loader_updates").is_some_and(|old| facts.get("loader_updates").is_some_and(|new| new != old)) {
            kept.insert("loader_update_seen".into(), format!("{at:.0}")); // an update was installed since the last reading
        }
        for kind in ["boot_file:", "boot_sector:", "boot_gap:"] {
            if facts.keys().any(|name| name.starts_with(kind)) {
                kept.retain(|name, _| !name.starts_with(kind) || facts.contains_key(name)); // a file or a disk that is gone
            }
        }
        if facts.keys().any(|name| name.starts_with("entry:")) {
            kept.retain(|name, _| !name.starts_with("entry:") || facts.contains_key(name)); // a boot entry that is gone
        }
        kept.extend(facts);
        if self.known.as_ref() != Some(&kept) || !self.path.exists() {
            let temporary = self.path.with_extension("tmp");
            if std::fs::write(&temporary, serde_json::to_string(&kept).unwrap_or_default()).is_ok() {
                let _ = std::fs::rename(&temporary, &self.path);
            }
        }
        self.known = Some(kept);
        found
    }

    pub fn known(&self) -> Option<&Facts> {
        self.known.as_ref()
    }
}

/// The reading, in the owner's words, for `garrett hardware`.
pub fn describe(facts: &Facts) -> Vec<String> {
    let mut lines = Vec::new();
    let is = |name: &str| facts.get(name).map(String::as_str).unwrap_or("");
    let or_unknown = |value: &str| if value.is_empty() { "could not be read here".to_string() } else { value.to_string() };
    lines.push(format!("  boot protection     {}", or_unknown(is("boot_protection"))));
    lines.push(format!("  firmware            {}{}", or_unknown(is("firmware")), if is("firmware_date").is_empty() { String::new() } else { format!(", dated {}", is("firmware_date")) }));
    lines.push(format!("  security chip       {}{}", or_unknown(is("security_chip")), if is("measure0").is_empty() { "" } else { ", firmware measurement kept" }));
    let count = |kind: &str| facts.keys().filter(|name| name.starts_with(kind)).count();
    lines.push(format!("  boot sectors        {}", if count("boot_sector:") == 0 { "could not be read here".to_string() } else { format!("{} disk(s) kept", count("boot_sector:")) }));
    lines.push(format!("  boot loader files   {}", if count("boot_file:") == 0 { "could not be read here".to_string() } else { format!("{} file(s) kept", count("boot_file:")) }));
    let entries: Vec<&str> = facts.iter().filter(|(name, _)| name.starts_with("entry:")).map(|(_, entry)| entry.split('|').next().unwrap_or("")).collect();
    lines.push(format!("  firmware boot list  {}", if entries.is_empty() { "could not be read here".to_string() } else { format!("{} entries: {}", entries.len(), entries.iter().take(6).copied().collect::<Vec<_>>().join(", ")) }));
    if facts.contains_key("loose_modules") {
        lines.push(format!("  kernel modules      {}", if is("loose_modules").is_empty() { "all loaded modules are installed ones".to_string() } else { format!("loaded from outside the installed set: {}", is("loose_modules")) }));
    }
    for (name, label) in [("driver_checks", "driver checks      "), ("kernel_lockdown", "kernel lockdown    "), ("memory_guard", "memory guard       ")] {
        if facts.contains_key(name) {
            lines.push(format!("  {label} {}", is(name)));
        }
    }
    lines
}
