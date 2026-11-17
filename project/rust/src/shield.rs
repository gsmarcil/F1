//! The privacy shield: measure first, then cut only what nothing depends on. On by default, on every system.
//!
//! It works below the operating system's own settings and changes none of them. Two things happen.
//!
//! Measuring. The names advertising and tracking networks are reached by (the list below) are looked up, and
//! every look at the machine notes which program holds a connection to one of their addresses. That record
//! stays on the machine (`garrett traffic`); it is never sent anywhere.
//!
//! Cutting. After a day of measuring, a tracker is refused at the firewall, by address, when all of this holds:
//! the address is in a network that belongs to the tracking company itself (the table below, read from the
//! address registries), so nothing else answers from it; no program other than a browser was seen using that
//! tracker on this machine, so nothing the owner runs depends on it; and the owner has not allowed it.
//! A tracker served from addresses it shares with sites people visit on purpose is measured and shown, and never
//! cut: refusing such an address would break those sites. Whenever something is unclear, traffic is left open.
//!
//! Nothing is ended, uninstalled or reconfigured here. The firewall entries are the agent's own table, removed
//! when it stops, and `garrett shield off` takes the shield away at once.

use crate::parse::{Conn, Proc};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

/// Names that serve advertising, tracking and analytics scripts or collect their reports. Each was answering in
/// DNS when it was added. No site people visit on purpose is here.
pub const TRACKERS: &[&str] = &[
    "google-analytics.com", "www.google-analytics.com", "ssl.google-analytics.com", "googletagmanager.com", "www.googletagmanager.com",
    "www.googletagservices.com", "stats.g.doubleclick.net", "ad.doubleclick.net", "googleads.g.doubleclick.net", "securepubads.g.doubleclick.net",
    "pubads.g.doubleclick.net", "pagead2.googlesyndication.com", "tpc.googlesyndication.com", "www.googleadservices.com", "adservice.google.com",
    "connect.facebook.net", "pixel.facebook.com", "an.facebook.com",
    "sb.scorecardresearch.com", "b.scorecardresearch.com", "static.hotjar.com", "script.hotjar.com", "static.criteo.net", "bidder.criteo.com",
    "cdn.taboola.com", "trc.taboola.com", "widgets.outbrain.com", "c.amazon-adsystem.com", "s.amazon-adsystem.com", "aax.amazon-adsystem.com",
    "ib.adnxs.com", "secure.adnxs.com", "fastlane.rubiconproject.com", "ads.pubmatic.com", "pixel.quantserve.com", "secure.quantserve.com",
    "analytics.tiktok.com", "static.ads-twitter.com", "analytics.twitter.com", "px.ads.linkedin.com", "snap.licdn.com", "ct.pinterest.com",
    "tr.snapchat.com", "sc-static.net", "cdn.mxpnl.com", "api.mixpanel.com", "api.segment.io", "cdn.segment.com", "api.amplitude.com",
    "cdn.amplitude.com", "mc.yandex.ru",
];

/// Networks registered to a tracking company itself, as the address registries (ARIN, RIPE) recorded them on
/// 2026-11-15: (first address, last address, the names that belong there). An address is only ever refused when
/// one of those names answers from it now AND it lies in that company's network. Never the whole network: the
/// same companies keep their customers' own pages in it.
pub const OWN_NETWORKS: &[(&str, &str, &[&str])] = &[
    ("74.119.116.0", "74.119.119.255", &["criteo.net", "criteo.com"]),                          // Criteo Corp.
    ("2620:100:a000::", "2620:100:a00f:ffff:ffff:ffff:ffff:ffff", &["criteo.net", "criteo.com"]), // Criteo Corp.
    ("68.67.128.0", "68.67.191.255", &["adnxs.com"]),                                           // Xandr Inc.
    ("216.19.192.0", "216.19.207.255", &["rubiconproject.com"]),                                // Magnite, Inc.
    ("2602:803:c000::", "2602:803:c00f:ffff:ffff:ffff:ffff:ffff", &["rubiconproject.com"]),     // Magnite, Inc.
    ("192.184.64.0", "192.184.79.255", &["quantserve.com"]),                                    // Quantcast Corporation
    ("2620:116:8000::", "2620:116:80ff:ffff:ffff:ffff:ffff:ffff", &["quantserve.com"]),         // Quantcast Corporation
    ("77.88.21.0", "77.88.21.255", &["mc.yandex.ru"]),                                          // YANDEX LLC
    ("87.250.250.0", "87.250.251.255", &["mc.yandex.ru"]),                                      // YANDEX LLC
    ("2a02:6b8::", "2a02:6b8:0:3:ffff:ffff:ffff:ffff", &["mc.yandex.ru"]),                      // YANDEX LLC
];

/// A host name: letters, digits, dots and hyphens, with a dot in it.
pub fn host_name(name: &str) -> Option<String> {
    let name = name.trim().trim_end_matches('.').to_ascii_lowercase();
    let fine = name.len() <= 253 && name.contains('.') && name.split('.').all(|part| !part.is_empty() && part.len() <= 63 && !part.starts_with('-') && !part.ends_with('-') && part.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-'));
    fine.then_some(name)
}

/// The company a tracker name belongs to, for the ones that run a network of their own: its names are judged
/// together, because a program that uses one of them is handed any of that company's addresses.
pub fn company(name: &str) -> Option<&'static str> {
    OWN_NETWORKS.iter().find(|(_, _, names)| names.iter().any(|suffix| name == *suffix || name.ends_with(&format!(".{suffix}")))).map(|(_, _, names)| names[0])
}

/// An address as a number that addresses of its own family can be compared by: (is it IPv6, the number).
fn number(address: &str) -> Option<(bool, u128)> {
    match address.parse::<IpAddr>().ok()? {
        IpAddr::V4(four) => Some((false, u32::from(four) as u128)),
        IpAddr::V6(six) => Some((true, u128::from(six))),
    }
}

/// True when this address is in the own network of the company that `name` belongs to.
pub fn in_own_network(name: &str, address: &str) -> bool {
    let Some(given) = number(address) else { return false };
    OWN_NETWORKS.iter().any(|(first, last, names)| {
        let (Some(first), Some(last)) = (number(first), number(last)) else { return false };
        first.0 == given.0 && (first.1..=last.1).contains(&given.1) && names.iter().any(|suffix| name == *suffix || name.ends_with(&format!(".{suffix}")))
    })
}

fn own(directory: &Path) -> Value {
    std::fs::read(directory.join("shield-own.json")).ok().and_then(|raw| serde_json::from_slice::<Value>(&raw).ok()).filter(Value::is_object).unwrap_or_else(|| json!({}))
}

fn save_own(directory: &Path, value: &Value) -> std::io::Result<()> {
    std::fs::create_dir_all(directory)?;
    std::fs::write(directory.join("shield-own.json"), value.to_string())
}

fn listed(value: &Value, key: &str) -> Vec<String> {
    value[key].as_array().into_iter().flatten().filter_map(Value::as_str).filter_map(host_name).collect()
}

/// Whether the shield is on: the owner's own choice (`garrett shield on|off`) if they made one, else `default`.
pub fn enabled(directory: &Path, default: bool) -> bool {
    own(directory)["enabled"].as_bool().unwrap_or(default)
}

pub fn set_enabled(directory: &Path, on: bool) -> std::io::Result<()> {
    let mut chosen = own(directory);
    chosen["enabled"] = json!(on);
    save_own(directory, &chosen)
}

/// The owner's word on one tracker. `allow`: never cut it. Otherwise: cut it even though a program here uses it.
pub fn choose(directory: &Path, name: &str, allow: bool) -> Result<String, String> {
    let name = host_name(name).ok_or("That is not a host name. Give a name like tracker.example.com.")?;
    if !TRACKERS.contains(&name.as_str()) {
        return Err(format!("{name} is not on the shield's list. See the list with: garrett shield"));
    }
    let mut chosen = own(directory);
    let (to, from) = if allow { ("allow", "cut") } else { ("cut", "allow") };
    let mut into = listed(&chosen, to);
    into.push(name.clone());
    into.sort();
    into.dedup();
    let rest: Vec<String> = listed(&chosen, from).into_iter().filter(|known| *known != name).collect();
    chosen[to] = json!(into);
    chosen[from] = json!(rest);
    save_own(directory, &chosen).map_err(|error| error.to_string())?;
    Ok(name)
}

/// A program seen holding a connection to a tracker.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Seen {
    pub looks: u64,
    pub first: f64,
    pub last: f64,
    pub browser: bool,
}

/// The shield's memory on one machine.
#[derive(Default)]
pub struct Shield {
    directory: PathBuf,
    /// address -> (tracker name, when a lookup last gave it)
    resolved: HashMap<String, (String, f64)>,
    /// (program, tracker) -> what was seen
    pub traffic: BTreeMap<(String, String), Seen>,
    /// Until when the shield only measures.
    pub measure_until: f64,
    saved: f64,
    dirty: bool,
}

const BROWSERS: &[&str] = &["chrome", "chrome.exe", "msedge.exe", "msedge", "firefox", "firefox.exe", "firefox-bin", "firefox-esr", "brave", "brave.exe", "brave-browser", "opera", "opera.exe",
    "vivaldi", "vivaldi.exe", "vivaldi-bin", "safari", "chromium", "chromium-browser", "arc", "arc.exe", "iexplore.exe", "msedgewebview2.exe", "com.apple.webkit.networking",
    "google chrome helper", "brave browser helper", "microsoft edge helper", "firefoxcp web content", "plugin-container", "web content"];

/// True for a web browser, by the name of its process.
pub fn is_browser(program: &str) -> bool {
    BROWSERS.contains(&program.to_lowercase().as_str())
}

impl Shield {
    /// Take up the shield's memory from the agent's folder. A machine the shield has not run on before measures
    /// for `hours` first.
    pub fn load(directory: &Path, hours: f64, now: f64) -> Shield {
        let kept = std::fs::read(directory.join("shield.json")).ok().and_then(|raw| serde_json::from_slice::<Value>(&raw).ok()).filter(Value::is_object);
        let mut shield = Shield { directory: directory.to_path_buf(), ..Shield::default() };
        match kept {
            Some(kept) => {
                shield.measure_until = kept["measure_until"].as_f64().unwrap_or(0.0);
                for row in kept["traffic"].as_array().into_iter().flatten() {
                    if let (Some(program), Some(tracker)) = (row["program"].as_str(), row["tracker"].as_str().filter(|name| TRACKERS.contains(name))) {
                        shield.traffic.insert((program.to_string(), tracker.to_string()), Seen { looks: row["looks"].as_u64().unwrap_or(1), first: row["first"].as_f64().unwrap_or(now), last: row["last"].as_f64().unwrap_or(now), browser: row["browser"].as_bool().unwrap_or(false) });
                    }
                }
            }
            None => {
                shield.measure_until = now + hours.clamp(0.0, 24.0 * 30.0) * 3600.0;
                shield.dirty = true;
            }
        }
        shield
    }

    /// What the tracker names answer from now: (name, address) pairs from a fresh lookup of each.
    pub fn learn_addresses(&mut self, found: &[(String, String)], now: f64) {
        for (name, address) in found {
            self.resolved.insert(address.clone(), (name.clone(), now));
        }
        // A tracker answers from many addresses and each lookup names a few: they are gathered over a day. One
        // that no lookup has given for a day is forgotten.
        self.resolved.retain(|_, (_, seen)| now - *seen <= 86_400.0);
    }

    /// One look at the machine: note every program that holds a connection out to a tracker's address.
    pub fn note(&mut self, procs: &[Proc], conns: &[Conn], now: f64) {
        for conn in conns.iter().filter(|conn| !conn.inbound) {
            let Some((tracker, _)) = self.resolved.get(&conn.raddr) else { continue };
            let Some(program) = procs.iter().find(|proc| proc.pid == conn.pid).map(|proc| proc.name.clone()).filter(|name| !name.is_empty()) else { continue };
            if self.traffic.len() >= 600 && !self.traffic.contains_key(&(program.clone(), tracker.clone())) {
                continue;
            }
            let browser = is_browser(&program);
            let seen = self.traffic.entry((program, tracker.clone())).or_insert(Seen { looks: 0, first: now, last: now, browser });
            seen.looks += 1;
            seen.last = now;
            self.dirty = true;
        }
        if self.dirty && now - self.saved >= 60.0 {
            self.save(now);
        }
    }

    /// The trackers some program other than a browser has used here in the last thirty days: something on this
    /// machine depends on them.
    pub fn depended_on(&self, now: f64) -> BTreeSet<&str> {
        self.traffic.iter().filter(|(_, seen)| !seen.browser && now - seen.last <= 30.0 * 86_400.0).map(|((_, tracker), _)| tracker.as_str()).collect()
    }

    /// The addresses to refuse at the firewall right now.
    pub fn cut(&self, now: f64) -> Vec<String> {
        if now < self.measure_until {
            return Vec::new();
        }
        let chosen = own(&self.directory);
        let (allowed, forced) = (listed(&chosen, "allow"), listed(&chosen, "cut"));
        // A company's names are judged together: allowed, needed or forced for one is so for all of them.
        let of = |names: &[String]| -> BTreeSet<&'static str> { names.iter().filter_map(|name| company(name)).collect() };
        let (allowed, forced) = (of(&allowed), of(&forced));
        let needed: BTreeSet<&'static str> = self.depended_on(now).into_iter().filter_map(company).collect();
        let mut found: Vec<String> = self.resolved.iter().filter(|(address, (name, _))| {
            in_own_network(name, address) && company(name).is_some_and(|who| !allowed.contains(who) && (forced.contains(who) || !needed.contains(who)))
        }).map(|(address, _)| address.clone()).collect();
        found.sort();
        found.truncate(100);
        found
    }

    pub fn save(&mut self, now: f64) {
        self.saved = now;
        self.dirty = false;
        let rows: Vec<Value> = self.traffic.iter().map(|((program, tracker), seen)| json!({"program": program, "tracker": tracker, "looks": seen.looks, "first": seen.first.trunc() as i64, "last": seen.last.trunc() as i64, "browser": seen.browser})).collect();
        let cut = self.cut(now);
        let cut_names: BTreeSet<&str> = cut.iter().filter_map(|address| self.resolved.get(address)).map(|(name, _)| name.as_str()).collect();
        let _ = std::fs::create_dir_all(&self.directory);
        let temporary = self.directory.join("shield.tmp");
        if std::fs::write(&temporary, json!({"measure_until": self.measure_until, "traffic": rows, "cut": cut_names, "addresses": cut.len(), "at": now.trunc() as i64}).to_string()).is_ok() {
            let _ = std::fs::rename(&temporary, self.directory.join("shield.json"));
        }
    }
}

/// Look every tracker name up, once. Slow (it waits for DNS): call it from a thread of its own.
pub fn look_up() -> Vec<(String, String)> {
    use std::net::ToSocketAddrs;
    let mut found = Vec::new();
    for name in TRACKERS {
        if let Ok(addresses) = (*name, 443).to_socket_addrs() {
            found.extend(addresses.take(16).filter_map(|address| crate::net::canonical(&address.ip().to_string())).map(|address| (name.to_string(), address)));
        }
    }
    found
}

/// What the shield has recorded on this machine, for the commands that show it.
pub fn recorded(directory: &Path) -> Value {
    std::fs::read(directory.join("shield.json")).ok().and_then(|raw| serde_json::from_slice::<Value>(&raw).ok()).filter(Value::is_object).unwrap_or_else(|| json!({}))
}

/// True for a tracker that can be cut by address at all: its company runs a network of its own.
pub fn has_own_network(name: &str) -> bool {
    OWN_NETWORKS.iter().any(|(_, _, names)| names.iter().any(|suffix| name == *suffix || name.ends_with(&format!(".{suffix}"))))
}

/// The owner's lists: (never cut, cut even though something here uses it).
pub fn choices(directory: &Path) -> (Vec<String>, Vec<String>) {
    let chosen = own(directory);
    (listed(&chosen, "allow"), listed(&chosen, "cut"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn folder(tag: &str) -> PathBuf {
        let folder = std::env::temp_dir().join(format!("garrett-shield-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&folder);
        std::fs::create_dir_all(&folder).unwrap();
        folder
    }

    fn proc(pid: u32, name: &str) -> Proc {
        Proc { pid, ppid: 1, name: name.into(), path: String::new(), started: 1 }
    }

    const T: f64 = 1_800_000_000.0;

    #[test]
    fn every_listed_name_is_a_plain_host_name_and_only_a_companys_own_network_counts() {
        assert!(TRACKERS.iter().all(|name| host_name(name).as_deref() == Some(*name)));
        let unique: BTreeSet<&&str> = TRACKERS.iter().collect();
        assert_eq!(unique.len(), TRACKERS.len());
        assert!(in_own_network("bidder.criteo.com", "74.119.117.5"));
        assert!(in_own_network("ib.adnxs.com", "68.67.160.132"));
        assert!(!in_own_network("ib.adnxs.com", "74.119.117.5"), "the right company's network, not just any listed one");
        assert!(!in_own_network("www.google-analytics.com", "142.250.139.100"), "an address shared with sites people visit is never one to cut");
        assert!(!in_own_network("static.hotjar.com", "3.164.92.39"));
        assert!(!in_own_network("notcriteo.com", "74.119.117.5") && !in_own_network("bidder.criteo.com", "2001:db8::1"));
        assert!(in_own_network("bidder.criteo.com", "2620:100:a00b::5") && in_own_network("mc.yandex.ru", "2a02:6b8::1:119") && in_own_network("mc.yandex.ru", "87.250.251.119"));
        assert!(!in_own_network("mc.yandex.ru", "2a02:6b8:1::1") && !in_own_network("pixel.quantserve.com", "2620:116:8100::1"));
        for (first, last, names) in OWN_NETWORKS {
            assert!(number(first).is_some() && number(last).is_some() && number(first) < number(last));
            assert!(names.iter().all(|suffix| TRACKERS.iter().any(|name| name == suffix || name.ends_with(&format!(".{suffix}")))), "{names:?}");
        }
    }

    #[test]
    fn it_measures_for_a_day_then_cuts_only_own_network_trackers_that_nothing_here_depends_on() {
        let folder = folder("a");
        let mut shield = Shield::load(&folder, 24.0, T);
        let found = vec![("bidder.criteo.com".to_string(), "74.119.117.5".to_string()), ("ib.adnxs.com".to_string(), "68.67.160.132".to_string()),
            ("www.google-analytics.com".to_string(), "142.250.139.100".to_string())];
        shield.learn_addresses(&found, T);
        let procs = vec![proc(10, "firefox"), proc(20, "billing-worker"), proc(30, "curl")];
        let conns = vec![Conn::new(10, 50000, "74.119.117.5", 443, false, "10.0.0.5"), Conn::new(10, 50001, "68.67.160.132", 443, false, "10.0.0.5"),
            Conn::new(20, 50002, "68.67.160.132", 443, false, "10.0.0.5"), Conn::new(30, 50003, "142.250.139.100", 443, false, "10.0.0.5"),
            Conn::new(30, 50004, "93.184.216.34", 443, false, "10.0.0.5"), Conn::new(10, 443, "74.119.117.5", 51000, true, "10.0.0.5")];
        shield.note(&procs, &conns, T + 10.0);
        assert_eq!(shield.traffic.len(), 4, "{:?}", shield.traffic.keys());
        assert!(shield.cut(T + 3600.0).is_empty(), "the first day is for measuring");
        // After the day: Criteo is cut (only the browser used it). Xandr stays open: a program of the owner's
        // uses it. Google's is never cut by address, whoever uses it.
        assert_eq!(shield.cut(T + 90_000.0), ["74.119.117.5"]);
        // The same company's other name, on another of its addresses, is left open with it: the program that
        // uses one may be handed the other next time.
        shield.learn_addresses(&[("secure.adnxs.com".to_string(), "68.67.160.117".to_string()), ("static.criteo.net".to_string(), "74.119.117.47".to_string())], T + 20.0);
        assert_eq!(shield.cut(T + 90_000.0), ["74.119.117.47", "74.119.117.5"]);
        assert_eq!(shield.depended_on(T + 90_000.0), BTreeSet::from(["ib.adnxs.com", "www.google-analytics.com"]));
        assert!(shield.depended_on(T + 40.0 * 86_400.0).is_empty(), "a program that stopped using it a month ago no longer holds it open");
        // The owner's word goes both ways.
        choose(&folder, "ib.adnxs.com", false).unwrap();
        assert_eq!(shield.cut(T + 90_000.0), ["68.67.160.117", "68.67.160.132", "74.119.117.47", "74.119.117.5"]);
        choose(&folder, "bidder.criteo.com", true).unwrap();
        assert_eq!(shield.cut(T + 90_000.0), ["68.67.160.117", "68.67.160.132"]);
        assert!(choose(&folder, "www.example.com", true).is_err());
        // What was measured is kept across a restart, and the day is not started again.
        shield.save(T + 90_000.0);
        let again = Shield::load(&folder, 24.0, T + 95_000.0);
        assert_eq!(again.traffic.len(), 4);
        assert_eq!(again.measure_until, shield.measure_until);
        assert_eq!(recorded(&folder)["cut"], json!(["ib.adnxs.com", "secure.adnxs.com"]));
        assert!(recorded(&folder)["traffic"][0]["last"].is_i64(), "times are kept as whole seconds");
        let _ = std::fs::remove_dir_all(&folder);
    }

    #[test]
    fn an_address_no_lookup_gives_any_more_is_forgotten() {
        let mut shield = Shield::load(&folder("b"), 0.0, T);
        shield.learn_addresses(&[("bidder.criteo.com".to_string(), "74.119.117.5".to_string())], T);
        assert_eq!(shield.cut(T + 60.0), ["74.119.117.5"]);
        shield.learn_addresses(&[("bidder.criteo.com".to_string(), "74.119.117.9".to_string())], T + 7.0 * 3600.0);
        assert_eq!(shield.cut(T + 7.0 * 3600.0), ["74.119.117.5", "74.119.117.9"], "addresses are gathered over a day");
        shield.learn_addresses(&[("bidder.criteo.com".to_string(), "74.119.117.9".to_string())], T + 30.0 * 3600.0);
        assert_eq!(shield.cut(T + 30.0 * 3600.0), ["74.119.117.9"]);
    }

    #[test]
    fn the_owner_can_switch_the_shield_off_and_that_outlasts_the_default() {
        let folder = folder("c");
        assert!(enabled(&folder, true) && !enabled(&folder, false));
        set_enabled(&folder, false).unwrap();
        assert!(!enabled(&folder, true));
        assert!(is_browser("Firefox") && is_browser("chrome.exe") && !is_browser("curl"));
        let _ = std::fs::remove_dir_all(&folder);
    }
}
