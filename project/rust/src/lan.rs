//! At the network card: who answers as this network's gateway, and who knocks on this machine's doors.
//!
//! Two things happen on the wire that no program on this machine starts, so watching programs never shows them:
//!
//!   - Another machine on the network starts answering for the gateway. From then on everything this machine
//!     sends out passes through it. The table of hardware addresses the system keeps shows it within a second:
//!     the gateway's hardware address becomes one that already belongs to another address on the network.
//!   - A machine on the network tries door after door: a port scan, which is how an intruder who is already
//!     inside looks for the next machine. On Linux the first packet of every connection attempt is read at the
//!     network card as it arrives: who sent it and which port it asked for. The header only; never what follows.
//!
//! A scan from the open internet is not reported: every machine with a public address gets them all day, and
//! there is nothing for its owner to do about one. Both findings are reported and nothing is done about them:
//! what is wrong is on another machine.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;

/// The gateway this machine sends through, and the hardware address the system holds for each neighbour.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Neighbours {
    pub gateway: String,
    /// address -> hardware address, lower case with colons.
    pub table: BTreeMap<String, String>,
}

fn hardware_address(found: &str) -> Option<String> {
    let parts: Vec<&str> = found.split([':', '-']).collect();
    if parts.len() != 6 || parts.iter().any(|part| part.is_empty() || part.len() > 2 || !part.bytes().all(|byte| byte.is_ascii_hexdigit())) {
        return None;
    }
    let plain: Vec<String> = parts.iter().map(|part| format!("{:0>2}", part.to_lowercase())).collect();
    let joined = plain.join(":");
    (joined != "00:00:00:00:00:00" && joined != "ff:ff:ff:ff:ff:ff").then_some(joined)
}

/// A Linux machine, read from the folder its files start at.
pub fn read_linux(root: &Path) -> Option<Neighbours> {
    // The route table: the line whose destination is everywhere names the gateway, its bytes last first.
    let routes = std::fs::read_to_string(root.join("proc/net/route")).ok()?;
    let gateway = routes.lines().skip(1).filter_map(|line| {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let through = u32::from_str_radix(fields.get(2)?, 16).ok()?;
        (fields.get(1) == Some(&"00000000") && through != 0).then(|| std::net::Ipv4Addr::from(through.swap_bytes()).to_string())
    }).next()?;
    let mut table = BTreeMap::new();
    for line in std::fs::read_to_string(root.join("proc/net/arp")).ok()?.lines().skip(1).take(2048) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        // Flags 0x0 is an entry still being asked about: it has no hardware address yet.
        if let (Some(address), Some(flags), Some(hardware)) = (fields.first(), fields.get(2), fields.get(3)) {
            if *flags != "0x0" && address.parse::<std::net::Ipv4Addr>().is_ok() {
                if let Some(hardware) = hardware_address(hardware) {
                    table.insert(address.to_string(), hardware);
                }
            }
        }
    }
    Some(Neighbours { gateway, table })
}

/// The same from what `arp -an` and `route -n get default` print (macOS and its relatives).
pub fn read_listing(neighbours: &str, route: &str) -> Option<Neighbours> {
    let gateway = route.lines().find_map(|line| line.trim().strip_prefix("gateway:")).map(|found| found.trim().to_string()).filter(|found| found.parse::<std::net::Ipv4Addr>().is_ok())?;
    let mut table = BTreeMap::new();
    for line in neighbours.lines().take(2048) {
        // "? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ..."
        let address = line.split('(').nth(1).and_then(|rest| rest.split(')').next()).filter(|found| found.parse::<std::net::Ipv4Addr>().is_ok());
        let hardware = line.split(" at ").nth(1).and_then(|rest| rest.split_whitespace().next()).and_then(hardware_address);
        if let (Some(address), Some(hardware)) = (address, hardware) {
            table.insert(address.to_string(), hardware);
        }
    }
    Some(Neighbours { gateway, table })
}

/// The same for the newer kind of address (IPv6), from what the system's own tools print: a list of neighbours
/// and the route out. Every system words these differently; what they share is that a line of the first holds an
/// address and a hardware address, and the second names the way out after "via", "gateway:" or "::/0".
pub fn read_listing6(neighbours: &str, route: &str) -> Option<Neighbours> {
    let address = |word: &str| word.split('%').next().and_then(|plain| plain.parse::<std::net::Ipv6Addr>().ok()).filter(|found| !found.is_multicast() && !found.is_unspecified() && !found.is_loopback());
    let words: Vec<&str> = route.split_whitespace().collect();
    let gateway = words.windows(2).find_map(|pair| (pair[0] == "via" || pair[0] == "gateway:" || pair[0] == "::/0").then(|| address(pair[1])).flatten())?.to_string();
    let mut table = BTreeMap::new();
    for line in neighbours.lines().take(2048) {
        let words: Vec<&str> = line.split_whitespace().collect();
        if let (Some(found), Some(hardware)) = (words.first().and_then(|word| address(word)), words.iter().skip(1).find_map(|word| hardware_address(word))) {
            table.insert(found.to_string(), hardware);
        }
    }
    Some(Neighbours { gateway, table })
}

/// This machine's neighbours and way out for the newer kind of address, asked of the system's own tools.
#[cfg(any(windows, target_os = "macos", target_os = "linux"))]
pub fn read6() -> Option<Neighbours> {
    let run = |arguments: &[&str]| crate::tool::run(arguments, None, std::time::Duration::from_secs(10)).unwrap_or_default();
    #[cfg(target_os = "linux")]
    let (neighbours, route) = (run(&["ip", "-6", "neigh", "show"]), run(&["ip", "-6", "route", "show", "default"]));
    #[cfg(target_os = "macos")]
    let (neighbours, route) = (run(&["/usr/sbin/ndp", "-an"]), run(&["/sbin/route", "-n", "get", "-inet6", "default"]));
    #[cfg(windows)]
    let (neighbours, route) = (run(&["netsh.exe", "interface", "ipv6", "show", "neighbors"]), run(&["route.exe", "print", "-6"]));
    read_listing6(&neighbours, &route)
}

#[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
pub fn read6() -> Option<Neighbours> {
    None
}

#[cfg(target_os = "linux")]
pub fn read() -> Option<Neighbours> {
    read_linux(Path::new("/"))
}

/// The network card this machine sends out through, from what `route -n get default` prints.
pub fn card_of(route: &str) -> Option<String> {
    route.lines().find_map(|line| line.trim().strip_prefix("interface:")).map(|found| found.trim().to_string())
        .filter(|found| !found.is_empty() && found.len() <= 15 && found.bytes().all(|byte| byte.is_ascii_alphanumeric()))
}

/// The network card this machine sends out through.
#[cfg(target_os = "macos")]
pub fn way_out_card() -> Option<String> {
    card_of(&crate::tool::run(&["/sbin/route", "-n", "get", "default"], None, std::time::Duration::from_secs(10)).unwrap_or_default())
}

#[cfg(target_os = "macos")]
pub fn read() -> Option<Neighbours> {
    let run = |arguments: &[&str]| crate::tool::run(arguments, None, std::time::Duration::from_secs(10)).unwrap_or_default();
    read_listing(&run(&["/usr/sbin/arp", "-an"]), &run(&["/sbin/route", "-n", "get", "default"]))
}

#[cfg(windows)]
pub fn read() -> Option<Neighbours> {
    use std::ffi::c_void;
    #[link(name = "iphlpapi")]
    extern "system" {
        fn GetIpNetTable(table: *mut c_void, size: *mut u32, sorted: i32) -> u32;
        fn GetIpForwardTable(table: *mut c_void, size: *mut u32, sorted: i32) -> u32;
    }
    // Both answers are a count, then rows of a fixed size. Asked twice: once for the size, once for the rows.
    let ask = |call: unsafe extern "system" fn(*mut c_void, *mut u32, i32) -> u32| -> Option<Vec<u8>> {
        let mut size = 0u32;
        unsafe { call(std::ptr::null_mut(), &mut size, 0) };
        if size == 0 || size > 4_194_304 {
            return None;
        }
        let mut buffer = vec![0u32; (size as usize).div_ceil(4) + 64];
        size = (buffer.len() * 4) as u32;
        if unsafe { call(buffer.as_mut_ptr() as *mut c_void, &mut size, 0) } != 0 {
            return None;
        }
        Some(buffer.iter().flat_map(|word| word.to_ne_bytes()).collect())
    };
    let word = |data: &[u8], at: usize| data.get(at..at + 4).map(|part| u32::from_ne_bytes([part[0], part[1], part[2], part[3]]));
    let address = |data: &[u8], at: usize| data.get(at..at + 4).map(|part| std::net::Ipv4Addr::new(part[0], part[1], part[2], part[3]).to_string());
    // Routes: 56 bytes each. Destination and mask both nothing is the way out; the lowest cost wins.
    let routes = ask(GetIpForwardTable)?;
    let mut best: Option<(u32, String)> = None;
    for row in 0..(word(&routes, 0)? as usize).min(4096) {
        let at = 4 + row * 56;
        if word(&routes, at) == Some(0) && word(&routes, at + 4) == Some(0) {
            if let (Some(through), Some(cost)) = (address(&routes, at + 12), word(&routes, at + 36)) {
                if through != "0.0.0.0" && best.as_ref().is_none_or(|(least, _)| cost < *least) {
                    best = Some((cost, through));
                }
            }
        }
    }
    let gateway = best?.1;
    // Neighbours: 24 bytes each: the card, the length of the hardware address, eight bytes for it, the address, the kind.
    let rows = ask(GetIpNetTable)?;
    let mut table = BTreeMap::new();
    for row in 0..(word(&rows, 0)? as usize).min(4096) {
        let at = 4 + row * 24;
        if word(&rows, at + 4) == Some(6) && word(&rows, at + 20).is_some_and(|kind| kind == 3 || kind == 4) {
            if let (Some(hardware), Some(found)) = (rows.get(at + 8..at + 14), address(&rows, at + 16)) {
                let text = hardware.iter().map(|byte| format!("{byte:02x}")).collect::<Vec<_>>().join(":");
                if let Some(hardware) = hardware_address(&text) {
                    table.insert(found, hardware);
                }
            }
        }
    }
    Some(Neighbours { gateway, table })
}

#[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
pub fn read() -> Option<Neighbours> {
    None
}

/// What was found on the wire: the signal, its points, the address it is about, and the sentence said about it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Found {
    pub signal: &'static str,
    pub points: i64,
    pub address: String,
    pub evidence: String,
}

/// Remembers the hardware address each gateway answered from, and says when another machine takes its place.
#[derive(Default)]
pub struct GatewayWatch {
    known: HashMap<String, String>,
    said: BTreeSet<String>,
    /// The neighbours of the reading before this one.
    before: BTreeMap<String, String>,
    /// When each gateway's hardware address last changed, newest last.
    changed: HashMap<String, Vec<f64>>,
}

impl GatewayWatch {
    /// Take a reading at this moment. A gateway that simply has a new hardware address (a new router) is learned
    /// again without a word. Two things are reported, once each: its address becoming the hardware address of a
    /// machine that was already on the network, and its address going back and forth, which is what the table
    /// does while the true gateway and an impostor both keep answering. The true address is kept, so nothing
    /// more is said when the network is put right.
    pub fn take(&mut self, seen: &Neighbours, at: f64) -> Option<Found> {
        let earlier = std::mem::replace(&mut self.before, seen.table.clone());
        let now = seen.table.get(&seen.gateway)?;
        let last = earlier.get(&seen.gateway).cloned();
        let Some(known) = self.known.get(&seen.gateway).cloned() else {
            self.known.insert(seen.gateway.clone(), now.clone());
            return None;
        };
        if last.as_ref().is_some_and(|last| last != now) {
            let changes = self.changed.entry(seen.gateway.clone()).or_default();
            changes.retain(|then| at - then <= 300.0);
            changes.push(at);
        }
        let flapping = self.changed.get(&seen.gateway).is_some_and(|changes| changes.len() >= 3);
        // A machine that was on the network a moment ago under this hardware address, as itself.
        let other = if &known == now { None } else { seen.table.iter().find(|(address, hardware)| *address != &seen.gateway && *hardware == now && earlier.get(*address) == Some(*hardware)).map(|(address, _)| address.clone()) };
        if other.is_none() && !flapping {
            if &known != now && self.changed.get(&seen.gateway).is_none_or(|changes| changes.len() <= 1) {
                self.known.insert(seen.gateway.clone(), now.clone()); // one change, and it stays: a new router
            }
            return None;
        }
        // Said once for each machine that takes the gateway's place, and once for a gateway that goes back and forth.
        let mark = match &other {
            Some(_) => format!("{}|{now}", seen.gateway),
            None => format!("{}|back and forth", seen.gateway),
        };
        if !self.said.insert(mark) {
            return None;
        }
        if self.said.len() > 256 {
            self.said.clear();
        }
        Some(match other {
            Some(other) => Found { signal: "gateway_impersonated", points: 6, address: other.clone(),
                evidence: format!("The gateway {} now answers from the hardware address of {other}, another machine on this network: what this machine sends out may be passing through it.", seen.gateway) },
            None => Found { signal: "gateway_impersonated", points: 6, address: seen.gateway.clone(),
                evidence: format!("The gateway {} keeps changing between two hardware addresses: a second machine is answering in its place, and what this machine sends out may be passing through it.", seen.gateway) },
        })
    }
}

/// How many different ports one neighbour may try in a minute before it is a scan.
pub const SCAN_PORTS: usize = 30;

/// Counts the ports each neighbour tried, from the first packet of each attempt.
#[derive(Default)]
pub struct ScanWatch {
    tried: HashMap<String, Vec<(f64, u16)>>,
    said: HashMap<String, f64>,
}

impl ScanWatch {
    /// One connection attempt that arrived: who sent it and the port it asked for. Returns a finding when this
    /// neighbour has tried enough different ports in the last minute, at most once an hour for each neighbour.
    pub fn attempt(&mut self, source: &str, port: u16, now: f64) -> Option<Found> {
        // A neighbour: a private address, or one that only works on this very network.
        let on_this_network = source.parse::<std::net::Ipv6Addr>().is_ok_and(|address| (address.segments()[0] & 0xffc0) == 0xfe80);
        if !crate::net::neighbour(source) && !on_this_network {
            return None; // the open internet, or this machine itself
        }
        if self.tried.len() >= 4096 {
            self.tried.retain(|_, list| list.last().is_some_and(|(at, _)| now - at <= 60.0));
            if self.tried.len() >= 4096 {
                return None;
            }
        }
        let list = self.tried.entry(source.to_string()).or_default();
        list.retain(|(at, _)| now - at <= 60.0);
        if list.len() < 512 {
            list.push((now, port));
        }
        let ports: BTreeSet<u16> = list.iter().map(|(_, port)| *port).collect();
        if ports.len() < SCAN_PORTS || self.said.get(source).is_some_and(|at| now - at < 3600.0) {
            return None;
        }
        self.said.insert(source.to_string(), now);
        list.clear();
        Some(Found { signal: "port_scan", points: 5, address: source.to_string(),
            evidence: format!("{source}, a machine on this network, tried {} different ports here in one minute: the way an intruder who is already inside looks for the next machine.", ports.len()) })
    }
}

/// (source address, destination port) of a packet that opens a TCP connection. `None` for anything else.
pub fn opening(packet: &[u8]) -> Option<(String, u16)> {
    if packet.first()? >> 4 == 6 {
        // The newer kind: a header of forty bytes, with what follows it named in its seventh byte.
        if packet.len() < 54 || packet[6] != 6 || packet[53] & 0x12 != 0x02 {
            return None;
        }
        let mut source = [0u8; 16];
        source.copy_from_slice(&packet[8..24]);
        return Some((std::net::Ipv6Addr::from(source).to_string(), u16::from_be_bytes([packet[42], packet[43]])));
    }
    let header = (*packet.first()? & 0x0f) as usize * 4;
    if packet[0] >> 4 != 4 || header < 20 || packet.len() < header + 14 || packet[9] != 6 || u16::from_be_bytes([packet[6], packet[7]]) & 0x1fff != 0 {
        return None;
    }
    if packet[header + 13] & 0x12 != 0x02 {
        return None; // not the first packet of an attempt
    }
    Some((std::net::Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]).to_string(), u16::from_be_bytes([packet[header + 2], packet[header + 3]])))
}

/// Read, at the network card, the first packet of every connection attempt that arrives, and hand each one's
/// sender and port to `seen` until `stop` says so. The kernel is given a filter, so nothing else ever reaches this
/// program, and only the first sixty-four bytes of those that do. Needs root. Returns at once where it cannot open.
#[cfg(target_os = "linux")]
pub fn listen(stop: &std::sync::atomic::AtomicBool, newer: bool, mut seen: impl FnMut(String, u16)) -> std::io::Result<()> {
    use std::sync::atomic::Ordering;
    #[repr(C)]
    struct Step {
        code: u16,
        yes: u8,
        no: u8,
        value: u32,
    }
    #[repr(C)]
    struct Program {
        length: u16,
        steps: *const Step,
    }
    let kind = if newer { libc::ETH_P_IPV6 } else { libc::ETH_P_IP };
    let handle = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, (kind as u16).to_be() as i32) };
    if handle < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // TCP, not a later piece of a split packet, with "open" set and "answer" not set: pass sixty-four bytes. Else nothing.
    let steps = [
        Step { code: 0x30, yes: 0, no: 0, value: 9 },
        Step { code: 0x15, yes: 0, no: 7, value: 6 },
        Step { code: 0x28, yes: 0, no: 0, value: 6 },
        Step { code: 0x45, yes: 5, no: 0, value: 0x1fff },
        Step { code: 0xb1, yes: 0, no: 0, value: 0 },
        Step { code: 0x50, yes: 0, no: 0, value: 13 },
        Step { code: 0x54, yes: 0, no: 0, value: 0x12 },
        Step { code: 0x15, yes: 0, no: 1, value: 0x02 },
        Step { code: 0x06, yes: 0, no: 0, value: 64 },
        Step { code: 0x06, yes: 0, no: 0, value: 0 },
    ];
    // The newer kind of packet: TCP straight after its fixed header, with "open" set and "answer" not set.
    let newer_steps = [
        Step { code: 0x30, yes: 0, no: 0, value: 6 },
        Step { code: 0x15, yes: 0, no: 4, value: 6 },
        Step { code: 0x30, yes: 0, no: 0, value: 53 },
        Step { code: 0x54, yes: 0, no: 0, value: 0x12 },
        Step { code: 0x15, yes: 0, no: 1, value: 0x02 },
        Step { code: 0x06, yes: 0, no: 0, value: 96 },
        Step { code: 0x06, yes: 0, no: 0, value: 0 },
    ];
    let program = if newer { Program { length: newer_steps.len() as u16, steps: newer_steps.as_ptr() } } else { Program { length: steps.len() as u16, steps: steps.as_ptr() } };
    let wait = libc::timeval { tv_sec: 1, tv_usec: 0 };
    let set = unsafe {
        libc::setsockopt(handle, libc::SOL_SOCKET, libc::SO_ATTACH_FILTER, &program as *const Program as *const libc::c_void, std::mem::size_of::<Program>() as libc::socklen_t) == 0
            && libc::setsockopt(handle, libc::SOL_SOCKET, libc::SO_RCVTIMEO, &wait as *const libc::timeval as *const libc::c_void, std::mem::size_of::<libc::timeval>() as libc::socklen_t) == 0
    };
    if !set {
        let error = std::io::Error::last_os_error();
        unsafe { libc::close(handle) };
        return Err(error);
    }
    let mut data = [0u8; 128];
    while !stop.load(Ordering::SeqCst) {
        let mut from: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        let mut length = std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t;
        let got = unsafe { libc::recvfrom(handle, data.as_mut_ptr() as *mut libc::c_void, data.len(), 0, &mut from as *mut libc::sockaddr_ll as *mut libc::sockaddr, &mut length) };
        if got < 0 {
            let error = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if error == libc::EAGAIN || error == libc::EWOULDBLOCK || error == libc::EINTR || error == libc::ENOBUFS {
                continue;
            }
            break;
        }
        // Only what arrives for this machine: not what it sends, and not what passes by for others.
        if from.sll_pkttype != 0 {
            continue;
        }
        if let Some((source, port)) = opening(&data[..got as usize]) {
            seen(source, port);
        }
    }
    unsafe { libc::close(handle) };
    Ok(())
}
