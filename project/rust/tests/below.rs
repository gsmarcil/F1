//! Below the operating system, on made-up machines: what is read from a Linux machine's own files, and which
//! changes between two readings are reported.

use garrett::hardware::{changes, day_number, describe, firmware_entries, read_linux, Facts, HardwareWatch};
use garrett::score::risky_commands;
use std::path::Path;

const GLOBAL: &str = "8be4df61-93ca-11d2-aa0d-00e098032b8c";
const T: f64 = 1_800_000_000.0;

fn write(root: &Path, name: &str, body: &[u8]) {
    let path = root.join(name);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, body).unwrap();
}

/// A firmware boot entry as the system hands it over: the variable's attributes, then the entry.
fn entry(name: &str, file: &str) -> Vec<u8> {
    let mut data = vec![7, 0, 0, 0, 1, 0, 0, 0, 0, 0];
    data.extend(name.encode_utf16().chain(std::iter::once(0)).flat_map(u16::to_le_bytes));
    data.extend(file.encode_utf16().flat_map(u16::to_le_bytes));
    data
}

fn machine(root: &Path) {
    write(root, &format!("sys/firmware/efi/efivars/SecureBoot-{GLOBAL}"), &[6, 0, 0, 0, 1]);
    write(root, &format!("sys/firmware/efi/efivars/Boot0000-{GLOBAL}"), &entry("ubuntu", "\\EFI\\ubuntu\\shimx64.efi"));
    write(root, &format!("sys/firmware/efi/efivars/BootOrder-{GLOBAL}"), &[7, 0, 0, 0, 0, 0]);
    write(root, "sys/class/dmi/id/bios_vendor", b"Example Firmware Co.\n");
    write(root, "sys/class/dmi/id/bios_version", b"F12\n");
    write(root, "sys/class/dmi/id/bios_date", b"03/15/2025\n");
    write(root, "sys/class/tpm/tpm0/pcr-sha256/0", b"A1B2C3D4E5F60718293A4B5C6D7E8F90A1B2C3D4E5F60718293A4B5C6D7E8F90\n");
    write(root, "proc/sys/kernel/osrelease", b"6.8.0-45-generic\n");
    write(root, "proc/modules", b"nvme 61440 3 - Live 0x0\nzfs 6000000 6 - Live 0x0 (PO)\nsnd_hda_intel 65536 2 - Live 0x0\n");
    write(root, "lib/modules/6.8.0-45-generic/modules.dep", b"kernel/drivers/nvme/host/nvme.ko.zst: kernel/drivers/nvme/host/nvme-core.ko.zst\nupdates/dkms/zfs.ko.zst:\nkernel/sound/pci/hda/snd-hda-intel.ko.zst:\n");
    write(root, "sys/kernel/security/lockdown", b"none [integrity] confidentiality\n");
    // One fixed disk laid out the old way, with a boot loader's core behind its first sector, a removable one
    // that is not read, and the boot loader's files on the firmware's partition.
    write(root, "sys/block/sda/removable", b"0\n");
    write(root, "sys/block/sdb/removable", b"1\n");
    write(root, "sys/block/loop0/removable", b"0\n");
    write(root, "dev/sda", &disk(b"boot code", b"the core of the boot loader"));
    write(root, "dev/sdb", &disk(b"a stick", b""));
    write(root, "boot/efi/EFI/ubuntu/shimx64.efi", b"shim");
    write(root, "boot/efi/EFI/ubuntu/grubx64.efi", b"grub");
    write(root, "boot/efi/EFI/BOOT/BOOTX64.EFI", b"fallback");
    write(root, "boot/efi/EFI/ubuntu/grub.cfg", b"configfile");
    write(root, "var/lib/dpkg/info/grub-efi-amd64-signed.list", b"/usr/lib/grub\n");
    write(root, "var/lib/dpkg/info/curl.list", b"/usr/bin/curl\n");
    // Every made-up machine installed its boot loader at the same moment, long ago.
    let installed = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
    for record in ["grub-efi-amd64-signed.list", "curl.list"] {
        std::fs::File::options().write(true).open(root.join("var/lib/dpkg/info").join(record)).unwrap().set_modified(installed).unwrap();
    }
}

/// The first megabyte of a disk laid out the old way: boot code, the disk's number, one partition that begins at
/// the usual place, the mark of a boot sector, and then whatever sits behind it.
fn disk(code: &[u8], behind: &[u8]) -> Vec<u8> {
    let mut data = vec![0u8; 1_048_576];
    data[..code.len()].copy_from_slice(code);
    data[440..444].copy_from_slice(&[1, 2, 3, 4]);
    data[446 + 4] = 0x83;
    data[446 + 8..446 + 12].copy_from_slice(&2048u32.to_le_bytes());
    data[510] = 0x55;
    data[511] = 0xaa;
    data[512..512 + behind.len()].copy_from_slice(behind);
    data
}

fn fresh(name: &str) -> std::path::PathBuf {
    let base = std::env::temp_dir().join(format!("garrett-below-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).unwrap();
    base
}

#[test]
fn a_linux_machine_is_read_from_its_own_files() {
    let root = fresh("read");
    machine(&root);
    let facts = read_linux(&root);
    assert_eq!(facts["boot_protection"], "on");
    assert_eq!(facts["firmware"], "Example Firmware Co. F12");
    assert_eq!(facts["firmware_date"], "03/15/2025");
    assert_eq!(facts["measure0"], "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90");
    assert!(facts["entry:Boot0000"].starts_with("ubuntu|"), "{facts:?}");
    assert!(!facts.contains_key("entry:BootOrde"), "the boot order is not an entry");
    assert_eq!(facts["loose_modules"], "", "a module with a dash in its file name and one built by the owner are both installed ones");
    assert_eq!(facts["kernel_lockdown"], "integrity");
    assert_eq!(facts["security_chip"], "present");
    assert!(describe(&facts).iter().any(|line| line.contains("boot protection") && line.ends_with("on")));
    // A machine that tells nothing (a container, an old board) gives nothing to compare, and nothing is made up.
    let bare = fresh("bare");
    let nothing = read_linux(&bare);
    assert!(!nothing.contains_key("boot_protection") && !nothing.contains_key("firmware") && !nothing.contains_key("loose_modules"), "{nothing:?}");
    assert!(changes(&nothing, &nothing, 0.0, T).is_empty());
    let _ = std::fs::remove_dir_all(&root);
    let _ = std::fs::remove_dir_all(&bare);
}

#[test]
fn each_change_an_update_does_not_explain_is_reported_and_an_update_is_not() {
    let root = fresh("change");
    machine(&root);
    let before = read_linux(&root);
    let after = |alter: &dyn Fn(&Path)| {
        let copy = fresh("change-after");
        machine(&copy);
        alter(&copy);
        let facts = read_linux(&copy);
        let _ = std::fs::remove_dir_all(&copy);
        facts
    };
    let signals = |facts: &Facts| -> Vec<&'static str> { changes(&before, facts, 0.0, T).into_iter().map(|change| change.signal).collect() };
    assert!(signals(&before).is_empty(), "nothing changed");

    assert_eq!(signals(&after(&|root| write(root, &format!("sys/firmware/efi/efivars/SecureBoot-{GLOBAL}"), &[6, 0, 0, 0, 0]))), ["boot_protection_off"]);
    assert_eq!(signals(&after(&|root| write(root, &format!("sys/firmware/efi/efivars/Boot0003-{GLOBAL}"), &entry("Windows Boot Manager", "\\EFI\\Microsoft\\Boot\\grubx64.efi")))), ["boot_entry_added"]);
    assert_eq!(signals(&after(&|root| write(root, &format!("sys/firmware/efi/efivars/Boot0000-{GLOBAL}"), &entry("ubuntu", "\\EFI\\ubuntu\\other.efi")))), ["boot_entry_added"], "the same name, another file");
    assert!(signals(&after(&|root| write(root, &format!("sys/firmware/efi/efivars/Boot0001-{GLOBAL}"), &entry("Linux-Firmware-Updater", "\\EFI\\ubuntu\\fwupdx64.efi")))).is_empty(), "the entry a firmware update makes for itself");
    assert_eq!(signals(&after(&|root| write(root, "sys/class/dmi/id/bios_date", b"06/01/2023\n"))), ["firmware_downgraded"]);
    assert_eq!(signals(&after(&|root| write(root, "sys/class/tpm/tpm0/pcr-sha256/0", b"FFFF\n"))), ["firmware_changed_unannounced"]);
    assert_eq!(signals(&after(&|root| write(root, "proc/modules", b"nvme 1 1 - Live 0x0\nzfs 1 1 - Live 0x0\nhideme 16384 0 - Live 0x0 (OE)\n"))), ["kernel_module_loose"]);
    // A firmware update: a new version, a later date, and with them a new measurement.
    let updated = after(&|root| {
        write(root, "sys/class/dmi/id/bios_version", b"F13\n");
        write(root, "sys/class/dmi/id/bios_date", b"09/30/2025\n");
        write(root, "sys/class/tpm/tpm0/pcr-sha256/0", b"0000\n");
    });
    assert!(signals(&updated).is_empty(), "{:?}", signals(&updated));
    // Windows says whether driver checks are on; a machine that never had Secure Boot on has not lost it.
    let mut windows = Facts::new();
    windows.insert("driver_checks".into(), "on".into());
    windows.insert("boot_protection".into(), "off".into());
    let mut later = windows.clone();
    later.insert("driver_checks".into(), "off".into());
    assert_eq!(changes(&windows, &later, 0.0, T).into_iter().map(|change| change.signal).collect::<Vec<_>>(), ["driver_checks_off"]);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn the_first_reading_is_the_starting_point_and_a_change_is_said_once() {
    let (root, state) = (fresh("watch-root"), fresh("watch-state"));
    machine(&root);
    let mut watch = HardwareWatch::new(&state);
    assert!(watch.take(read_linux(&root), T).is_empty(), "nothing is reported from the first reading");
    assert!(watch.take(read_linux(&root), T).is_empty());
    write(&root, &format!("sys/firmware/efi/efivars/SecureBoot-{GLOBAL}"), &[6, 0, 0, 0, 0]);
    assert_eq!(watch.take(read_linux(&root), T).len(), 1);
    assert!(watch.take(read_linux(&root), T).is_empty(), "said once");
    // The reading is kept between runs: an agent that starts again does not begin from nothing.
    write(&root, "proc/modules", b"hideme 16384 0 - Live 0x0 (OE)\n");
    let mut again = HardwareWatch::new(&state);
    assert_eq!(again.take(read_linux(&root), T).into_iter().map(|change| change.subject).collect::<Vec<_>>(), ["kernel module hideme"]);
    // A fact that cannot be read for a moment keeps its value: the next good reading is compared with the last good one.
    std::fs::remove_file(root.join("sys/class/tpm/tpm0/pcr-sha256/0")).unwrap();
    assert!(again.take(read_linux(&root), T).is_empty());
    write(&root, "sys/class/tpm/tpm0/pcr-sha256/0", b"FFFF\n");
    assert_eq!(again.take(read_linux(&root), T).into_iter().map(|change| change.signal).collect::<Vec<_>>(), ["firmware_changed_unannounced"]);
    let _ = std::fs::remove_dir_all(&root);
    let _ = std::fs::remove_dir_all(&state);
}

#[test]
fn dates_boot_listings_and_the_commands_that_reach_below_the_system_are_read_right() {
    assert_eq!(day_number("03/15/2025"), Some(20250315));
    assert_eq!(day_number("2025-03-15"), Some(20250315));
    assert_eq!(day_number("15 March"), None);
    assert_eq!(day_number(""), None);
    let listing = "Firmware Boot Manager\r\n---------------------\r\nidentifier              {fwbootmgr}\r\ndisplayorder            {bootmgr}\r\n                        {5f0a1b2c-0000-0000-0000-000000000001}\r\ntimeout                 1\r\n\r\nWindows Boot Manager\r\n--------------------\r\nidentifier              {bootmgr}\r\ndevice                  partition=\\Device\\HarddiskVolume1\r\npath                    \\EFI\\Microsoft\\Boot\\bootmgfw.efi\r\ndescription             Windows Boot Manager\r\n\r\nFirmware Application (101fffff)\r\n-------------------------------\r\nidentifier              {5f0a1b2c-0000-0000-0000-000000000001}\r\ndescription             USB Drive\r\n";
    assert_eq!(firmware_entries(listing), vec![("{bootmgr}".to_string(), "\\EFI\\Microsoft\\Boot\\bootmgfw.efi".to_string())]);
    let labels = |line: &str| -> Vec<&'static str> { risky_commands().iter().filter(|(pattern, _)| pattern.is_match(line)).map(|(_, label)| *label).collect() };
    for (line, label) in [
        ("insmod /tmp/.x/hideme.ko", "a kernel module loaded from a temporary or home folder"),
        ("bcdedit /set testsigning on", "driver signature checks switched off for the next start"),
        ("mokutil --disable-validation", "the system's check of what may run switched off"),
        ("spctl --master-disable", "the system's check of what may run switched off"),
        ("flashrom -p internal -w /tmp/bios.bin", "the firmware chip written from the running system"),
    ] {
        assert!(labels(line).contains(&label), "{line}: {:?}", labels(line));
    }
    for line in ["modprobe zfs", "insmod /lib/modules/6.8.0-45-generic/extra/zfs.ko", "bcdedit /set testsigning off", "mokutil --sb-state", "spctl --status", "flashrom -p internal -r /root/backup.bin"] {
        assert!(labels(line).is_empty(), "{line}: {:?}", labels(line));
    }
}

#[derive(Default)]
struct Machine;

impl garrett::watch::Sensor for Machine {
    fn system(&self) -> &str {
        "linux"
    }
    fn processes(&mut self) -> Vec<garrett::parse::Proc> {
        Vec::new()
    }
    fn connections(&mut self) -> Vec<garrett::parse::Conn> {
        Vec::new()
    }
    fn command_lines(&mut self, _pids: &[u32]) -> std::collections::HashMap<u32, String> {
        std::collections::HashMap::new()
    }
    fn file_age(&mut self, _path: &str, _now: f64) -> Option<f64> {
        None
    }
}

struct Still;

impl garrett::watch::Hands for Still {
    fn suspend(&mut self, _pid: u32) -> bool {
        panic!("nothing is held for a change below the system")
    }
    fn resume(&mut self, _pid: u32) -> bool {
        true
    }
    fn kill(&mut self, _pid: u32) -> bool {
        panic!("nothing is ended for a change below the system")
    }
    fn block(&mut self, _addresses: &[String]) -> Option<bool> {
        Some(true)
    }
}

#[test]
fn a_change_below_the_system_becomes_one_case_that_nothing_is_done_about() {
    use garrett::watch::{Mode, Watcher};
    let mut watcher = Watcher::new(Machine, Some(Still), &"a".repeat(64), Mode::Kill, "");
    let mut before = Facts::new();
    before.insert("boot_protection".into(), "on".into());
    let mut now = before.clone();
    now.insert("boot_protection".into(), "off".into());
    watcher.hardware_changed(&changes(&before, &now, 0.0, T), 1_800_000_000.0);
    let cases = watcher.tick_with(1_800_000_001.0, &[]);
    assert_eq!(cases.len(), 1, "{cases:?}");
    assert_eq!(cases[0]["level"], "SUSPECT");
    assert_eq!(cases[0]["signals"][0]["id"], "boot_protection_off");
    assert_eq!(cases[0]["categories"][0], "hardware");
    assert!(cases[0].get("actions").is_none() && cases[0].get("cleanup").is_none());
}

#[test]
fn the_code_a_machine_starts_from_is_kept_and_a_change_no_update_explains_is_reported() {
    let root = fresh("boot");
    machine(&root);
    let before = read_linux(&root);
    assert!(before.contains_key("boot_sector:sda") && before.contains_key("boot_gap:sda"), "{before:?}");
    assert!(!before.keys().any(|name| name.contains("sdb") || name.contains("loop0")), "a removable disk is not read");
    let files: Vec<&str> = before.keys().filter_map(|name| name.strip_prefix("boot_file:")).collect();
    assert_eq!(files, ["efi/boot/bootx64.efi", "efi/ubuntu/grubx64.efi", "efi/ubuntu/shimx64.efi"], "the loader's programs, not its settings");
    assert!(before.contains_key("loader_updates"));
    let signals = |facts: &Facts, updated: f64| -> Vec<String> { changes(&before, facts, updated, T).into_iter().map(|change| format!("{}: {}", change.signal, change.subject)).collect() };

    // Each of the three places, changed with nothing installed.
    write(&root, "dev/sda", &disk(b"other code", b"the core of the boot loader"));
    assert_eq!(signals(&read_linux(&root), 0.0), ["boot_code_changed: the boot sector of sda"]);
    write(&root, "dev/sda", &disk(b"boot code", b"another core"));
    assert_eq!(signals(&read_linux(&root), 0.0).len(), 1);
    assert!(signals(&read_linux(&root), 0.0)[0].contains("the space behind the boot sector of sda"));
    write(&root, "dev/sda", &disk(b"boot code", b"the core of the boot loader"));
    write(&root, "boot/efi/EFI/ubuntu/grubx64.efi", b"not grub");
    assert_eq!(signals(&read_linux(&root), 0.0), ["boot_code_changed: the boot loader file efi/ubuntu/grubx64.efi"]);
    write(&root, "boot/efi/EFI/ubuntu/grubx64.efi", b"grub");
    write(&root, "boot/efi/EFI/ubuntu/extra.efi", b"new");
    assert_eq!(signals(&read_linux(&root), 0.0), ["boot_code_changed: the boot loader file efi/ubuntu/extra.efi"], "a loader file that was not there");
    std::fs::remove_file(root.join("boot/efi/EFI/ubuntu/extra.efi")).unwrap();
    // Repartitioning the disk, or giving it another number, changes no code.
    let mut repartitioned = disk(b"boot code", b"the core of the boot loader");
    repartitioned[440..444].copy_from_slice(&[9, 9, 9, 9]);
    repartitioned[446 + 16 + 4] = 0x83;
    repartitioned[446 + 16 + 8..446 + 16 + 12].copy_from_slice(&900_000u32.to_le_bytes());
    write(&root, "dev/sda", &repartitioned);
    assert!(signals(&read_linux(&root), 0.0).is_empty());
    // Changing the loader's settings is not a change of code.
    write(&root, "boot/efi/EFI/ubuntu/grub.cfg", b"another configfile");
    assert!(signals(&read_linux(&root), 0.0).is_empty());

    // A boot loader update: its files, its core and the firmware's entry change, and its package's record with them.
    write(&root, "boot/efi/EFI/ubuntu/grubx64.efi", b"grub, the next version");
    write(&root, "dev/sda", &disk(b"boot code", b"the next core"));
    write(&root, &format!("sys/firmware/efi/efivars/Boot0000-{GLOBAL}"), &entry("ubuntu", "\\EFI\\ubuntu\\shimx64.efi, again"));
    assert_eq!(signals(&read_linux(&root), 0.0).len(), 3, "without the package's record, all three are reported");
    let record = root.join("var/lib/dpkg/info/grub-efi-amd64-signed.list");
    std::fs::File::options().write(true).open(&record).unwrap().set_modified(std::time::SystemTime::now() + std::time::Duration::from_secs(3600)).unwrap();
    assert!(signals(&read_linux(&root), 0.0).is_empty(), "the update explains them");
    // Another package being installed explains nothing.
    let unrelated = fresh("boot-unrelated");
    machine(&unrelated);
    let start = read_linux(&unrelated);
    write(&unrelated, "boot/efi/EFI/ubuntu/grubx64.efi", b"not grub");
    std::fs::File::options().write(true).open(unrelated.join("var/lib/dpkg/info/curl.list")).unwrap().set_modified(std::time::SystemTime::now() + std::time::Duration::from_secs(3600)).unwrap();
    assert_eq!(changes(&start, &read_linux(&unrelated), 0.0, T).len(), 1);
    // What an update goes on to change at the next start is still its doing for a day, and no longer.
    let mut watch = HardwareWatch::new(&fresh("boot-state"));
    let late = fresh("boot-late");
    machine(&late);
    assert!(watch.take(read_linux(&late), T).is_empty());
    std::fs::File::options().write(true).open(late.join("var/lib/dpkg/info/grub-efi-amd64-signed.list")).unwrap().set_modified(std::time::SystemTime::now() + std::time::Duration::from_secs(7200)).unwrap();
    assert!(watch.take(read_linux(&late), T + 300.0).is_empty());
    write(&late, &format!("sys/firmware/efi/efivars/Boot0000-{GLOBAL}"), &entry("ubuntu", "\\EFI\\ubuntu\\shimx64.efi, rewritten at the next start"));
    assert!(watch.take(read_linux(&late), T + 3600.0).is_empty(), "within the day");
    write(&late, "boot/efi/EFI/ubuntu/shimx64.efi", b"not shim");
    assert_eq!(watch.take(read_linux(&late), T + 3.0 * 86400.0).len(), 1, "days later it is not");
    for folder in [&root, &unrelated, &late] {
        let _ = std::fs::remove_dir_all(folder);
    }
}

#[test]
fn the_partitions_windows_boot_entries_start_from_are_found_in_its_listing() {
    use garrett::hardware::firmware_partitions;
    let listing = "identifier              {bootmgr}\r\ndevice                  partition=\\Device\\HarddiskVolume1\r\npath                    \\EFI\\Microsoft\\Boot\\bootmgfw.efi\r\n\r\nidentifier              {x}\r\ndevice                  partition=\\Device\\HarddiskVolume1\r\n\r\ndevice                  partition=C:\r\ndevice                  partition=\\Device\\Else\\..\\x\r\n";
    assert_eq!(firmware_partitions(listing), ["\\Device\\HarddiskVolume1"]);
}
