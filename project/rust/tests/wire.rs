//! At the network card, on made-up networks: a machine that takes the gateway's place, and one that tries door
//! after door.

use garrett::lan::{opening, read_linux, read_listing, read_listing6, GatewayWatch, Neighbours, ScanWatch, SCAN_PORTS};

const T: f64 = 1_800_000_000.0;

fn network(pairs: &[(&str, &str)]) -> Neighbours {
    Neighbours { gateway: "192.168.1.1".into(), table: pairs.iter().map(|(address, hardware)| (address.to_string(), hardware.to_string())).collect() }
}

#[test]
fn a_machine_that_takes_the_gateways_place_is_reported_once_and_a_new_router_is_not() {
    let router = "aa:aa:aa:aa:aa:01";
    let mut watch = GatewayWatch::default();
    let quiet = network(&[("192.168.1.1", router), ("192.168.1.20", "bb:bb:bb:bb:bb:20"), ("192.168.1.30", "cc:cc:cc:cc:cc:30")]);
    assert_eq!(watch.take(&quiet, T), None, "the first reading is the starting point");
    assert_eq!(watch.take(&quiet, T), None);
    // The machine at .30 starts answering for the gateway.
    let taken = network(&[("192.168.1.1", "cc:cc:cc:cc:cc:30"), ("192.168.1.20", "bb:bb:bb:bb:bb:20"), ("192.168.1.30", "cc:cc:cc:cc:cc:30")]);
    let found = watch.take(&taken, T).expect("reported");
    assert_eq!((found.signal, found.points, found.address.as_str()), ("gateway_impersonated", 6, "192.168.1.30"));
    assert!(found.evidence.contains("192.168.1.1") && found.evidence.contains("192.168.1.30"));
    assert_eq!(watch.take(&taken, T), None, "said once while it lasts");
    assert_eq!(watch.take(&quiet, T), None, "and nothing when the network is put right");
    assert_eq!(watch.take(&taken, T), None, "nor when the same machine does it again");
    // A new router: a hardware address nobody else on the network has.
    let mut other = GatewayWatch::default();
    assert_eq!(other.take(&quiet, T), None);
    let replaced = network(&[("192.168.1.1", "dd:dd:dd:dd:dd:02"), ("192.168.1.20", "bb:bb:bb:bb:bb:20")]);
    assert_eq!(other.take(&replaced, T), None);
    assert_eq!(other.take(&replaced, T), None);
    // A router that has two addresses of its own from the start is how that network is.
    let mut two = GatewayWatch::default();
    let both = network(&[("192.168.1.1", router), ("192.168.1.254", router)]);
    assert_eq!(two.take(&both, T), None);
    assert_eq!(two.take(&both, T), None);
    // Nothing is known about a gateway that has not answered yet.
    assert_eq!(GatewayWatch::default().take(&network(&[("192.168.1.20", "bb:bb:bb:bb:bb:20")]), T), None);
}

#[test]
fn the_systems_own_tables_are_read_on_linux_and_from_a_listing() {
    let root = std::env::temp_dir().join(format!("garrett-wire-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("proc/net")).unwrap();
    std::fs::write(root.join("proc/net/route"), "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\neth0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\neth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n").unwrap();
    std::fs::write(root.join("proc/net/arp"), "IP address       HW type     Flags       HW address            Mask     Device\n192.168.1.1      0x1         0x2         AA:AA:AA:AA:AA:01     *        eth0\n192.168.1.20     0x1         0x2         bb:bb:bb:bb:bb:20     *        eth0\n192.168.1.99     0x1         0x0         00:00:00:00:00:00     *        eth0\n").unwrap();
    let seen = read_linux(&root).expect("read");
    assert_eq!(seen.gateway, "192.168.1.1");
    assert_eq!(seen.table.get("192.168.1.1").map(String::as_str), Some("aa:aa:aa:aa:aa:01"));
    assert_eq!(seen.table.len(), 2, "an address still being asked about has no hardware address");
    let _ = std::fs::remove_dir_all(&root);
    let listed = read_listing("? (192.168.1.1) at aa:aa:aa:aa:aa:1 on en0 ifscope [ethernet]\n? (192.168.1.20) at bb:bb:bb:bb:bb:20 on en0 ifscope [ethernet]\n? (192.168.1.99) at (incomplete) on en0 ifscope [ethernet]\n? (224.0.0.251) at 1:0:5e:0:0:fb on en0 ifscope permanent [ethernet]\n",
        "   route to: default\ndestination: default\n       mask: default\n    gateway: 192.168.1.1\n  interface: en0\n").expect("read");
    assert_eq!(listed.gateway, "192.168.1.1");
    assert_eq!(listed.table.get("192.168.1.1").map(String::as_str), Some("aa:aa:aa:aa:aa:01"), "written out in full");
    assert!(!listed.table.contains_key("192.168.1.99"));
    assert_eq!(read_listing("", "route: writing to routing socket: not in table\n"), None, "a machine with no way out has no gateway to watch");
    assert_eq!(garrett::lan::card_of("   route to: default\n    gateway: 192.168.1.1\n  interface: en0\n      flags: <UP,GATEWAY>\n").as_deref(), Some("en0"));
    assert_eq!(garrett::lan::card_of("route: writing to routing socket: not in table\n"), None);
    assert_eq!(garrett::lan::card_of("  interface: en0; rm -rf /\n"), None, "only a plain name is a card");
}

#[test]
fn a_neighbour_that_tries_door_after_door_is_a_scan_and_ordinary_traffic_is_not() {
    let mut watch = ScanWatch::default();
    // A neighbour that opens many connections to the same few services.
    for attempt in 0..400 {
        assert_eq!(watch.attempt("192.168.1.20", [22, 80, 443][attempt % 3], T + attempt as f64 * 0.1), None);
    }
    // One that walks the ports.
    let mut found = None;
    for port in 1..=SCAN_PORTS as u16 {
        found = watch.attempt("192.168.1.30", port, T + f64::from(port) * 0.01);
        assert_eq!(found.is_some(), usize::from(port) == SCAN_PORTS, "port {port}");
    }
    let found = found.unwrap();
    assert_eq!((found.signal, found.points, found.address.as_str()), ("port_scan", 5, "192.168.1.30"));
    for port in 1000..1200 {
        assert_eq!(watch.attempt("192.168.1.30", port, T + 10.0), None, "said once an hour");
    }
    // The same number of ports spread over an hour is not a scan.
    for port in 1..=200u16 {
        assert_eq!(watch.attempt("192.168.1.40", port, T + f64::from(port) * 20.0), None);
    }
    // The open internet scans every machine all day: nothing is said, and this machine is not its own neighbour.
    for port in 1..=500u16 {
        assert_eq!(watch.attempt("93.184.216.34", port, T), None);
        assert_eq!(watch.attempt("127.0.0.1", port, T), None);
    }
}

#[test]
fn only_the_first_packet_of_an_attempt_is_read_and_only_its_sender_and_port() {
    // An IPv4 header of twenty bytes, then the start of a TCP header.
    let packet = |flags: u8, protocol: u8, piece: u16| {
        let mut data = vec![0u8; 40];
        data[0] = 0x45;
        data[6..8].copy_from_slice(&piece.to_be_bytes());
        data[9] = protocol;
        data[12..16].copy_from_slice(&[192, 168, 1, 30]);
        data[16..20].copy_from_slice(&[192, 168, 1, 5]);
        data[20..22].copy_from_slice(&51000u16.to_be_bytes());
        data[22..24].copy_from_slice(&8443u16.to_be_bytes());
        data[33] = flags;
        data
    };
    assert_eq!(opening(&packet(0x02, 6, 0)), Some(("192.168.1.30".to_string(), 8443)));
    assert_eq!(opening(&packet(0x12, 6, 0)), None, "an answer to this machine's own attempt");
    assert_eq!(opening(&packet(0x10, 6, 0)), None, "a packet of a connection that is already open");
    assert_eq!(opening(&packet(0x02, 17, 0)), None, "not TCP");
    assert_eq!(opening(&packet(0x02, 6, 0x00b9)), None, "a later piece of a split packet");
    assert_eq!(opening(&packet(0x02, 6, 0)[..30]), None, "cut short");
    assert_eq!(opening(&[]), None);
    let mut longer = packet(0x02, 6, 0);
    longer[0] = 0x46; // a header with options: four bytes more
    longer.splice(20..20, [0u8; 4]);
    assert_eq!(opening(&longer), Some(("192.168.1.30".to_string(), 8443)));
}

#[test]
fn an_impostor_that_was_never_seen_as_itself_shows_as_a_gateway_that_goes_back_and_forth() {
    let (router, impostor) = ("aa:aa:aa:aa:aa:01", "ee:ee:ee:ee:ee:66");
    let reading = |hardware: &str| network(&[("192.168.1.1", hardware), ("192.168.1.20", "bb:bb:bb:bb:bb:20")]);
    let mut watch = GatewayWatch::default();
    assert_eq!(watch.take(&reading(router), T), None);
    // The true gateway and the impostor both keep answering: the table holds now one, now the other.
    assert_eq!(watch.take(&reading(impostor), T + 2.0), None, "one change could be a new router");
    assert_eq!(watch.take(&reading(router), T + 4.0), None);
    let found = watch.take(&reading(impostor), T + 6.0).expect("the third change in a few seconds");
    assert_eq!((found.signal, found.address.as_str()), ("gateway_impersonated", "192.168.1.1"));
    assert!(found.evidence.contains("keeps changing"));
    assert_eq!(watch.take(&reading(router), T + 8.0), None);
    assert_eq!(watch.take(&reading(impostor), T + 10.0), None, "said once");
    // A new router that comes with a second address of its own is a new router.
    let mut replaced = GatewayWatch::default();
    assert_eq!(replaced.take(&reading(router), T), None);
    let new_router = network(&[("192.168.1.1", "dd:dd:dd:dd:dd:02"), ("192.168.1.254", "dd:dd:dd:dd:dd:02"), ("192.168.1.20", "bb:bb:bb:bb:bb:20")]);
    assert_eq!(replaced.take(&new_router, T + 2.0), None);
    assert_eq!(replaced.take(&new_router, T + 4.0), None);
    // Two changes far apart are two routers over the years.
    let mut slow = GatewayWatch::default();
    assert_eq!(slow.take(&reading(router), T), None);
    assert_eq!(slow.take(&reading(impostor), T + 86400.0), None);
    assert_eq!(slow.take(&reading(router), T + 2.0 * 86400.0), None);
    assert_eq!(slow.take(&reading("dd:dd:dd:dd:dd:02"), T + 3.0 * 86400.0), None);
}

#[test]
fn the_newer_kind_of_address_is_read_from_each_systems_own_words_and_watched_the_same_way() {
    let linux = read_listing6("fe80::1 dev eth0 lladdr aa:aa:aa:aa:aa:01 router REACHABLE\nfe80::20 dev eth0 lladdr bb:bb:bb:bb:bb:20 STALE\nfe80::99 dev eth0 FAILED\n2001:db8::5 dev eth0 lladdr bb:bb:bb:bb:bb:20 STALE\n",
        "default via fe80::1 dev eth0 proto ra metric 100 pref medium\n").expect("read");
    assert_eq!(linux.gateway, "fe80::1");
    assert_eq!(linux.table.len(), 3);
    assert_eq!(linux.table.get("fe80::1").map(String::as_str), Some("aa:aa:aa:aa:aa:01"));
    let mac = read_listing6("Neighbor                        Linklayer Address  Netif Expire    St Flgs Prbs\nfe80::1%en0                     aa:aa:aa:aa:aa:1   en0 23h59m58s S  R\nfe80::20%en0                    bb:bb:bb:bb:bb:20  en0 expired   S\nfe80::99%en0                    (incomplete)       en0 expired   N\n",
        "   route to: default\ndestination: default\n    gateway: fe80::1%en0\n  interface: en0\n").expect("read");
    assert_eq!((mac.gateway.as_str(), mac.table.len()), ("fe80::1", 2));
    let windows = read_listing6("Interface 12: Ethernet\r\n\r\nInternet Address                              Physical Address   Type\r\n--------------------------------------------  -----------------  -----------\r\nfe80::1                                       aa-aa-aa-aa-aa-01  Reachable (Router)\r\nfe80::20                                      bb-bb-bb-bb-bb-20  Stale\r\nff02::1                                       33-33-00-00-00-01  Permanent\r\n",
        "Active Routes:\r\n If Metric Network Destination      Gateway\r\n  1    331 ::1/128                  On-link\r\n 12    281 ::/0                     fe80::1\r\n 12    281 fe80::/64                On-link\r\n").expect("read");
    assert_eq!((windows.gateway.as_str(), windows.table.len()), ("fe80::1", 2));
    assert_eq!(windows.table.get("fe80::1"), linux.table.get("fe80::1"));
    assert_eq!(read_listing6("", "Active Routes:\r\n  1    331 ::1/128                  On-link\r\n"), None, "no way out of this kind");
    // One machine holds several addresses of this kind under one hardware address; that is not an impostor.
    let mut watch = GatewayWatch::default();
    assert_eq!(watch.take(&linux, T), None);
    assert_eq!(watch.take(&linux, T + 30.0), None);
    let mut taken = linux.clone();
    taken.table.insert("fe80::1".into(), "bb:bb:bb:bb:bb:20".into());
    let found = watch.take(&taken, T + 60.0).expect("reported");
    assert!(found.address == "2001:db8::5" || found.address == "fe80::20", "{found:?}");
    // A neighbour of this kind that walks the ports is a scan too.
    let mut scan = ScanWatch::default();
    let mut said = None;
    for port in 1..=SCAN_PORTS as u16 {
        said = scan.attempt("fe80::20", port, T);
    }
    assert_eq!(said.map(|found| found.signal), Some("port_scan"));
    for port in 1..=200u16 {
        assert_eq!(scan.attempt("2606:4700::1111", port, T), None, "the open internet");
    }
    let mut packet = vec![0u8; 60];
    packet[0] = 0x60;
    packet[6] = 6;
    packet[8] = 0xfe;
    packet[9] = 0x80;
    packet[23] = 0x20;
    packet[42..44].copy_from_slice(&8443u16.to_be_bytes());
    packet[53] = 0x02;
    assert_eq!(opening(&packet), Some(("fe80::20".to_string(), 8443)));
    packet[53] = 0x12;
    assert_eq!(opening(&packet), None);
}

// The system names one function of a device with a colon, which a Windows folder cannot carry.
#[cfg(unix)]
#[test]
fn a_keyboard_never_seen_before_is_noticed_and_the_ones_this_machine_has_had_are_not() {
    use garrett::devices::{keyboards_linux, KeyboardWatch};
    let base = std::env::temp_dir().join(format!("garrett-keyboards-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let (root, state) = (base.join("root"), base.join("state"));
    std::fs::create_dir_all(&state).unwrap();
    let device = |name: &str, maker: &str, model: &str, class: &str, protocol: &str| {
        let folder = root.join("sys/bus/usb/devices");
        std::fs::create_dir_all(folder.join(name)).unwrap();
        std::fs::create_dir_all(folder.join(format!("{name}:1.0"))).unwrap();
        std::fs::write(folder.join(name).join("idVendor"), format!("{maker}\n")).unwrap();
        std::fs::write(folder.join(name).join("idProduct"), format!("{model}\n")).unwrap();
        std::fs::write(folder.join(format!("{name}:1.0")).join("bInterfaceClass"), format!("{class}\n")).unwrap();
        std::fs::write(folder.join(format!("{name}:1.0")).join("bInterfaceProtocol"), format!("{protocol}\n")).unwrap();
    };
    device("1-1", "046d", "c31c", "03", "01"); // the keyboard on the desk
    device("1-2", "046d", "c077", "03", "02"); // a mouse
    device("1-3", "0781", "5581", "08", "50"); // a memory stick
    let present = keyboards_linux(&root).expect("read");
    assert_eq!(present.into_iter().collect::<Vec<_>>(), ["046d:c31c:"]);
    let mut watch = KeyboardWatch::new(&state);
    assert_eq!(watch.take(&keyboards_linux(&root).unwrap()), 0, "the first reading is the starting point");
    // A stick that says it is a keyboard.
    device("1-4", "16c0", "27db", "03", "01");
    assert_eq!(watch.take(&keyboards_linux(&root).unwrap()), 1);
    assert_eq!(watch.take(&keyboards_linux(&root).unwrap()), 0);
    // Unplugged and plugged in again, and after the agent starts again: it has been seen.
    std::fs::remove_dir_all(root.join("sys/bus/usb/devices/1-4:1.0")).unwrap();
    assert_eq!(watch.take(&keyboards_linux(&root).unwrap()), 0);
    device("1-4", "16c0", "27db", "03", "01");
    assert_eq!(KeyboardWatch::new(&state).take(&keyboards_linux(&root).unwrap()), 0);
    assert_eq!(keyboards_linux(&base.join("nothing")), None, "a machine that does not tell");
    let _ = std::fs::remove_dir_all(&base);
}
