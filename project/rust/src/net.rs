//! Which addresses are the open internet. The tables are the ones Python's `ipaddress` module uses for
//! `is_global` (as of Python 3.13), written out here.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

fn v4(a: u8, b: u8, c: u8, d: u8, bits: u32) -> (u32, u32) {
    (u32::from(Ipv4Addr::new(a, b, c, d)), if bits == 0 { 0 } else { u32::MAX << (32 - bits) })
}

fn v6(text: &str, bits: u32) -> (u128, u128) {
    (u128::from(text.parse::<Ipv6Addr>().expect("a fixed table entry")), if bits == 0 { 0 } else { u128::MAX << (128 - bits) })
}

fn within4(address: u32, nets: &[(u32, u32)]) -> bool {
    nets.iter().any(|(net, mask)| address & mask == *net)
}

fn within6(address: u128, nets: &[(u128, u128)]) -> bool {
    nets.iter().any(|(net, mask)| address & mask == *net)
}

fn private4(address: u32) -> bool {
    let nets = [
        v4(0, 0, 0, 0, 8), v4(10, 0, 0, 0, 8), v4(127, 0, 0, 0, 8), v4(169, 254, 0, 0, 16), v4(172, 16, 0, 0, 12),
        v4(192, 0, 0, 0, 24), v4(192, 0, 0, 170, 31), v4(192, 0, 2, 0, 24), v4(192, 168, 0, 0, 16), v4(198, 18, 0, 0, 15),
        v4(198, 51, 100, 0, 24), v4(203, 0, 113, 0, 24), v4(240, 0, 0, 0, 4), v4(255, 255, 255, 255, 32),
    ];
    let exceptions = [v4(192, 0, 0, 9, 32), v4(192, 0, 0, 10, 32)];
    within4(address, &nets) && !within4(address, &exceptions)
}

fn private6(address: u128) -> bool {
    let nets = [
        v6("::1", 128), v6("::", 128), v6("::ffff:0:0", 96), v6("64:ff9b:1::", 48), v6("100::", 64), v6("2001::", 23),
        v6("2001:db8::", 32), v6("2002::", 16), v6("3fff::", 20), v6("5f00::", 16), v6("fc00::", 7), v6("fe80::", 10),
    ];
    let exceptions = [v6("2001:1::1", 128), v6("2001:1::2", 128), v6("2001:3::", 32), v6("2001:4:112::", 48), v6("2001:20::", 28), v6("2001:30::", 28)];
    within6(address, &nets) && !within6(address, &exceptions)
}

/// An address as written, without any `%zone`. IPv4 written inside IPv6 (`::ffff:1.2.3.4`) is the IPv4 address.
pub fn parse(address: &str) -> Option<IpAddr> {
    let plain = address.split('%').next().unwrap_or("");
    match plain.parse::<IpAddr>().ok()? {
        IpAddr::V6(value) => Some(value.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(value))),
        other => Some(other),
    }
}

/// True for an address on the open internet.
pub fn is_internet(address: &str) -> bool {
    match parse(address) {
        Some(IpAddr::V4(value)) => {
            let number = u32::from(value);
            !within4(number, &[v4(100, 64, 0, 0, 10)]) && !private4(number)
        }
        Some(IpAddr::V6(value)) => !private6(u128::from(value)),
        None => false,
    }
}

/// An address in its usual written form (IPv4 inside IPv6 as IPv4), or `None` when it is not an address.
pub fn canonical(address: &str) -> Option<String> {
    parse(address).map(|value| value.to_string())
}

/// A private address on the organisation's own network: not the internet, not this machine.
/// Carrier-grade and overlay ranges (100.64.0.0/10) are neighbours too: anything that is not the open internet.
pub fn neighbour(address: &str) -> bool {
    if is_internet(address) {
        return false;
    }
    match parse(address) {
        Some(IpAddr::V4(value)) => !(value.is_loopback() || value.is_link_local() || value.is_unspecified() || value.is_multicast()),
        Some(IpAddr::V6(value)) => !(value.is_loopback() || value.is_unspecified() || value.is_multicast() || (value.segments()[0] & 0xffc0) == 0xfe80),
        None => false,
    }
}

/// True for this machine talking to itself.
pub fn is_loopback(address: &str) -> bool {
    match parse(address) {
        Some(IpAddr::V4(value)) => value.is_loopback(),
        Some(IpAddr::V6(value)) => value.is_loopback(),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_open_internet_and_everything_that_is_not() {
        for address in ["93.184.216.34", "8.8.8.8", "192.0.0.9", "224.0.0.5", "2606:2800:220:1::1", "::ffff:93.184.216.35", "2001:4:112::1"] {
            assert!(is_internet(address), "{address}");
        }
        for address in ["10.0.0.5", "127.0.0.1", "100.64.1.1", "169.254.169.254", "198.51.100.7", "203.0.113.9", "192.168.1.1", "::1", "fe80::1%eth0", "fc00::1", "2001:db8::1", "::ffff:10.0.0.1", "not an address", ""] {
            assert!(!is_internet(address), "{address}");
        }
        assert!(is_loopback("127.0.0.1") && is_loopback("::1") && is_loopback("::ffff:127.0.0.1") && !is_loopback("10.0.0.1"));
    }
}
