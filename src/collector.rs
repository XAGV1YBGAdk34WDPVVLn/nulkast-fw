use crate::api::WsEvent;
use crate::config::FwConfig;
use crate::dns;
use crate::store::{now_unix, NewDnsQuery, NewFlow, StoreEvent, StoreWriter};
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;
use tokio::sync::broadcast;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedNeighbor {
    pub ip: String,
    pub mac: String,
    pub iface: String,
}

/// Parse `ip neigh show` output to discover active LAN devices even when DHCP is disabled.
pub fn parse_ip_neigh(output: &str, lan_ifaces: &HashSet<String>) -> Vec<ParsedNeighbor> {
    let mut out = Vec::new();
    for line in output.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 {
            continue;
        }
        let ip = parts[0];
        if ip.contains(':') {
            continue; // IPv4 focus in Phase 2
        }
        let mut iface = None;
        let mut mac = None;
        let mut i = 1;
        while i + 1 < parts.len() {
            match parts[i] {
                "dev" => {
                    iface = Some(parts[i + 1]);
                    i += 2;
                }
                "lladdr" => {
                    mac = Some(parts[i + 1].to_lowercase());
                    i += 2;
                }
                _ => i += 1,
            }
        }
        let state = parts.last().copied().unwrap_or("");
        if matches!(state, "FAILED" | "INCOMPLETE") {
            continue;
        }
        if let (Some(dev), Some(lladdr)) = (iface, mac) {
            if lan_ifaces.is_empty() || lan_ifaces.contains(dev) {
                out.push(ParsedNeighbor {
                    ip: ip.to_string(),
                    mac: lladdr,
                    iface: dev.to_string(),
                });
            }
        }
    }
    out
}

/// Parse a single line of `conntrack -L` output into a `NewFlow`.
pub fn parse_conntrack_line(line: &str, ts: u64) -> Option<NewFlow> {
    let tokens: Vec<&str> = line.split_whitespace().collect();
    if tokens.len() < 6 {
        return None;
    }
    let proto = tokens[0].to_string();
    if !matches!(proto.as_str(), "tcp" | "udp" | "icmp") {
        return None;
    }

    let mut state = String::from("ACTIVE");
    let mut src_ip = None;
    let mut dst_ip = None;
    let mut src_port: u16 = 0;
    let mut dst_port: u16 = 0;
    let mut bytes_orig: u64 = 0;
    let mut bytes_reply: u64 = 0;
    let mut seen_first_src = false;
    let mut bytes_seen = 0;

    for tok in &tokens[2..] {
        if !tok.contains('=') && !tok.starts_with('[') && tok.chars().all(|c| c.is_ascii_uppercase() || c == '_') {
            state = (*tok).to_string();
            continue;
        }
        if let Some((k, v)) = tok.split_once('=') {
            match k {
                "src" => {
                    if !seen_first_src {
                        src_ip = Some(v.to_string());
                        seen_first_src = true;
                    }
                }
                "dst" => {
                    if dst_ip.is_none() {
                        dst_ip = Some(v.to_string());
                    }
                }
                "sport" => {
                    if src_port == 0 {
                        src_port = v.parse().unwrap_or(0);
                    }
                }
                "dport" => {
                    if dst_port == 0 {
                        dst_port = v.parse().unwrap_or(0);
                    }
                }
                "bytes" => {
                    let b = v.parse::<u64>().unwrap_or(0);
                    if bytes_seen == 0 {
                        bytes_orig = b;
                    } else if bytes_seen == 1 {
                        bytes_reply = b;
                    }
                    bytes_seen += 1;
                }
                _ => {}
            }
        }
    }

    let src = src_ip?;
    let dst = dst_ip?;
    // Skip loopback noise
    if src.starts_with("127.") && dst.starts_with("127.") {
        return None;
    }

    Some(NewFlow {
        ts,
        proto,
        src_ip: src,
        src_port,
        dst_ip: dst,
        dst_port,
        bytes_orig,
        bytes_reply,
        state,
    })
}

/// Parse a dnsmasq `query[TYPE] <domain> from <client_ip>` log line.
pub fn parse_dnsmasq_query_line(
    line: &str,
    ts: u64,
    blocked_domains: &HashSet<String>,
) -> Option<NewDnsQuery> {
    let idx = line.find("query[")?;
    let rest = &line[idx + "query[".len()..];
    let close = rest.find(']')?;
    let qtype = rest[..close].trim().to_string();
    let after = rest[close + 1..].trim();
    // Expected: "<domain> from <client_ip>"
    let mut parts = after.split_whitespace();
    let domain = parts.next()?.to_lowercase();
    let kw = parts.next()?;
    if kw != "from" {
        return None;
    }
    let client_ip = parts.next()?.to_string();
    let action = if is_domain_blocked(&domain, blocked_domains) {
        "sinkholed".to_string()
    } else {
        "allowed".to_string()
    };

    Some(NewDnsQuery {
        ts,
        client_ip,
        domain,
        qtype,
        action,
    })
}

fn is_domain_blocked(domain: &str, blocked: &HashSet<String>) -> bool {
    if blocked.contains(domain) {
        return true;
    }
    let mut s = domain;
    while let Some((_, parent)) = s.split_once('.') {
        if blocked.contains(parent) {
            return true;
        }
        s = parent;
    }
    false
}

/// Spawn async background collector for devices (leases + ip neigh), conntrack flows, and dnsmasq queries.
pub fn spawn_collectors(
    config_path: PathBuf,
    state_dir: PathBuf,
    writer: StoreWriter,
    events_tx: broadcast::Sender<WsEvent>,
) {
    // 1. Device + Flow collector (every 2 seconds)
    let cfg_path_1 = config_path.clone();
    let st_dir_1 = state_dir.clone();
    let writer_1 = writer.clone();
    let ev_tx_1 = events_tx.clone();
    tokio::spawn(async move {
        let mut seen_flows: HashMap<String, (u64, u64)> = HashMap::new();
        let mut tick = tokio::time::interval(Duration::from_secs(2));
        loop {
            tick.tick().await;
            let cfg = FwConfig::load(&cfg_path_1).ok();
            let lan_ifaces: HashSet<String> = cfg
                .as_ref()
                .map(|c| c.interfaces.lan.iter().cloned().collect())
                .unwrap_or_default();
            let ts = now_unix();

            // Read DHCP leases
            let leases = dns::read_leases(&st_dir_1);
            for l in leases {
                writer_1.try_send(StoreEvent::UpsertDevice {
                    mac: l.mac.clone(),
                    ip: l.ip.clone(),
                    hostname: l.hostname.clone(),
                    ts,
                });
            }

            // Read `ip neigh show` in blocking pool
            let lan_clone = lan_ifaces.clone();
            let neighs = tokio::task::spawn_blocking(move || {
                Command::new("ip")
                    .args(["neigh", "show"])
                    .output()
                    .ok()
                    .filter(|o| o.status.success())
                    .map(|o| parse_ip_neigh(&String::from_utf8_lossy(&o.stdout), &lan_clone))
                    .unwrap_or_default()
            })
            .await
            .unwrap_or_default();

            for n in neighs {
                writer_1.try_send(StoreEvent::UpsertDevice {
                    mac: n.mac,
                    ip: n.ip,
                    hostname: String::new(),
                    ts,
                });
            }

            // Read `conntrack -L` in blocking pool
            let flows = tokio::task::spawn_blocking(move || {
                Command::new("conntrack")
                    .arg("-L")
                    .output()
                    .ok()
                    .filter(|o| o.status.success())
                    .map(|o| {
                        String::from_utf8_lossy(&o.stdout)
                            .lines()
                            .filter_map(|line| parse_conntrack_line(line, ts))
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default()
            })
            .await
            .unwrap_or_default();

            for f in flows {
                let key = format!(
                    "{}:{}:{}:{}:{}",
                    f.proto, f.src_ip, f.src_port, f.dst_ip, f.dst_port
                );
                let changed = match seen_flows.get(&key) {
                    Some(&(bo, br)) => bo != f.bytes_orig || br != f.bytes_reply,
                    None => true,
                };
                if changed {
                    seen_flows.insert(key, (f.bytes_orig, f.bytes_reply));
                    let _ = ev_tx_1.send(WsEvent::Flow(f.clone()));
                    writer_1.try_send(StoreEvent::RecordFlow(f));
                }
            }
            if seen_flows.len() > 4096 {
                seen_flows.clear();
            }
        }
    });

    // 2. DNS log tailer (every 1 second)
    tokio::spawn(async move {
        let log_path = state_dir.join("dnsmasq.log");
        let mut offset: u64 = 0;
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        loop {
            tick.tick().await;
            let (new_offset, lines) = read_new_lines(&log_path, offset);
            offset = new_offset;
            if lines.is_empty() {
                continue;
            }
            let blocked: HashSet<String> = FwConfig::load(&config_path)
                .map(|c| c.blocked_domains.into_iter().map(|d| d.to_lowercase()).collect())
                .unwrap_or_default();
            let ts = now_unix();
            for line in lines {
                if let Some(q) = parse_dnsmasq_query_line(&line, ts, &blocked) {
                    let _ = events_tx.send(WsEvent::DnsQuery(q.clone()));
                    writer.try_send(StoreEvent::RecordDnsQuery(q));
                }
            }
        }
    });
}

fn read_new_lines(path: &Path, mut offset: u64) -> (u64, Vec<String>) {
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(_) => return (0, Vec::new()),
    };
    let len = match file.metadata() {
        Ok(m) => m.len(),
        Err(_) => return (offset, Vec::new()),
    };
    if len < offset {
        offset = 0; // log rotated/truncated
    }
    if len == offset {
        return (offset, Vec::new());
    }
    if file.seek(SeekFrom::Start(offset)).is_err() {
        return (offset, Vec::new());
    }
    let mut buf = String::new();
    if file.read_to_string(&mut buf).is_err() {
        return (offset, Vec::new());
    }
    let new_offset = offset + buf.len() as u64;
    let lines = buf.lines().map(|l| l.to_string()).collect();
    (new_offset, lines)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_conntrack_tcp_line() {
        let line = "tcp      6 431999 ESTABLISHED src=10.100.0.20 dst=10.200.0.2 sport=54321 dport=8080 packets=5 bytes=412 src=10.200.0.2 dst=10.200.0.10 sport=8080 dport=54321 packets=4 bytes=980 [ASSURED] mark=0 use=1";
        let f = parse_conntrack_line(line, 12345).expect("must parse");
        assert_eq!(f.proto, "tcp");
        assert_eq!(f.state, "ESTABLISHED");
        assert_eq!(f.src_ip, "10.100.0.20");
        assert_eq!(f.src_port, 54321);
        assert_eq!(f.dst_ip, "10.200.0.2");
        assert_eq!(f.dst_port, 8080);
        assert_eq!(f.bytes_orig, 412);
        assert_eq!(f.bytes_reply, 980);
    }

    #[test]
    fn parses_dnsmasq_query_and_sinkhole_match() {
        let mut blocked = HashSet::new();
        blocked.insert("bad.test".to_string());

        let q1 = parse_dnsmasq_query_line(
            "Nov 22 19:55:01 dnsmasq[42]: query[A] sub.bad.test from 10.100.0.20",
            100,
            &blocked,
        )
        .unwrap();
        assert_eq!(q1.domain, "sub.bad.test");
        assert_eq!(q1.qtype, "A");
        assert_eq!(q1.client_ip, "10.100.0.20");
        assert_eq!(q1.action, "sinkholed");

        let q2 = parse_dnsmasq_query_line(
            "Nov 22 19:55:01 dnsmasq[42]: query[AAAA] good.test from 10.100.0.20",
            101,
            &blocked,
        )
        .unwrap();
        assert_eq!(q2.action, "allowed");
    }

    #[test]
    fn parses_ip_neigh_lan_devices() {
        let sample = "10.100.0.20 dev lan0 lladdr 02:42:ac:11:00:02 REACHABLE\n10.200.0.2 dev wan0 lladdr aa:bb:cc:dd:ee:01 STALE\n";
        let mut lan = HashSet::new();
        lan.insert("lan0".to_string());
        let parsed = parse_ip_neigh(sample, &lan);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].ip, "10.100.0.20");
        assert_eq!(parsed[0].mac, "02:42:ac:11:00:02");
    }
}
