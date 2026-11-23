pub mod dns_wire;
pub mod nfqueue;
pub mod tls;

use crate::feeds::SuricataRule;
use crate::store::{now_unix, NewAlert};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex, RwLock};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IdsMode {
    Alert,
    Drop,
}

impl IdsMode {
    pub fn from_str(s: &str) -> Self {
        if s.eq_ignore_ascii_case("drop") {
            Self::Drop
        } else {
            Self::Alert
        }
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Alert => "alert",
            Self::Drop => "drop",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketVerdict {
    Accept,
    Drop,
}

#[derive(Debug, Clone)]
pub struct InspectOutcome {
    pub verdict: PacketVerdict,
    pub alerts: Vec<NewAlert>,
}

#[derive(Debug, Clone, Serialize)]
pub struct IdsStats {
    pub enabled: bool,
    pub mode: String,
    pub queues: u16,
    pub blocked_domains: usize,
    pub ja4_rules: usize,
    pub suricata_rules: usize,
    pub detect_dns_bypass: bool,
}

pub struct RuleEngine {
    pub enabled: bool,
    pub mode: IdsMode,
    pub queues: u16,
    pub detect_dns_bypass: bool,
    pub port_scan_threshold: usize,
    pub blocked_domains: HashSet<String>,
    pub ja4_blocklist: HashMap<String, String>,
    pub suricata_rules: Vec<SuricataRule>,
    port_scan_window: Mutex<HashMap<(String, String), (u64, HashSet<u16>)>>,
}

impl RuleEngine {
    pub fn new(
        enabled: bool,
        mode: IdsMode,
        queues: u16,
        detect_dns_bypass: bool,
        port_scan_threshold: usize,
        blocked_domains: Vec<String>,
    ) -> Self {
        Self {
            enabled,
            mode,
            queues,
            detect_dns_bypass,
            port_scan_threshold: port_scan_threshold.max(3),
            blocked_domains: blocked_domains.into_iter().map(|d| d.to_lowercase()).collect(),
            ja4_blocklist: HashMap::new(),
            suricata_rules: Vec::new(),
            port_scan_window: Mutex::new(HashMap::new()),
        }
    }

    pub fn stats(&self) -> IdsStats {
        IdsStats {
            enabled: self.enabled,
            mode: self.mode.as_str().to_string(),
            queues: self.queues,
            blocked_domains: self.blocked_domains.len(),
            ja4_rules: self.ja4_blocklist.len(),
            suricata_rules: self.suricata_rules.len(),
            detect_dns_bypass: self.detect_dns_bypass,
        }
    }

    fn domain_matches(host: &str, target: &str) -> bool {
        host == target || host.ends_with(&format!(".{}", target))
    }

    fn is_domain_blocked(&self, host: &str) -> bool {
        if self.blocked_domains.contains(host) {
            return true;
        }
        let mut s = host;
        while let Some((_, parent)) = s.split_once('.') {
            if self.blocked_domains.contains(parent) {
                return true;
            }
            s = parent;
        }
        false
    }

    fn record_port_touch(&self, src_ip: &str, dst_ip: &str, dst_port: u16, now: u64) -> bool {
        let mut map = match self.port_scan_window.lock() {
            Ok(m) => m,
            Err(_) => return false,
        };
        if map.len() > 2048 {
            map.retain(|_, (ts, _)| now.saturating_sub(*ts) <= 15);
        }
        let key = (src_ip.to_string(), dst_ip.to_string());
        let entry = map.entry(key).or_insert_with(|| (now, HashSet::new()));
        if now.saturating_sub(entry.0) > 10 {
            entry.0 = now;
            entry.1.clear();
        }
        entry.1.insert(dst_port);
        entry.1.len() == self.port_scan_threshold
    }
}

pub type SharedRuleEngine = Arc<RwLock<RuleEngine>>;

/// Inspect a raw IPv4 packet from NFQUEUE (zero-panic on arbitrary/malformed bytes).
pub fn inspect_ipv4_packet(pkt: &[u8], engine: &RuleEngine) -> InspectOutcome {
    let mut alerts = Vec::new();
    let mut should_drop = false;

    if pkt.len() < 20 || (pkt[0] >> 4) != 4 {
        return InspectOutcome {
            verdict: PacketVerdict::Accept,
            alerts,
        };
    }
    let ihl = ((pkt[0] & 0x0f) as usize) * 4;
    if ihl < 20 || pkt.len() < ihl {
        return InspectOutcome {
            verdict: PacketVerdict::Accept,
            alerts,
        };
    }

    let proto = pkt[9];
    let src_ip = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]).to_string();
    let dst_ip = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]).to_string();
    let l4 = &pkt[ihl..];
    let ts = now_unix();

    match proto {
        // TCP (6)
        6 if l4.len() >= 20 => {
            let dst_port = u16::from_be_bytes([l4[2], l4[3]]);
            let tcp_hdr_len = ((l4[12] >> 4) as usize) * 4;
            let tcp_flags = l4[13];

            // Behavioral LAN port-scan detection on TCP SYN
            if (tcp_flags & 0x02) != 0 && (tcp_flags & 0x10) == 0 {
                if engine.record_port_touch(&src_ip, &dst_ip, dst_port, ts) {
                    alerts.push(NewAlert {
                        ts,
                        severity: "medium".into(),
                        category: "port_scan".into(),
                        action: "alert".into(),
                        src_ip: src_ip.clone(),
                        dst_ip: dst_ip.clone(),
                        dst_port,
                        indicator: format!("{} distinct ports/10s", engine.port_scan_threshold),
                        detail: format!("LAN host {} scanning ports on {}", src_ip, dst_ip),
                    });
                }
            }

            if tcp_hdr_len >= 20 && l4.len() > tcp_hdr_len {
                let payload = &l4[tcp_hdr_len..];
                if let Some(ch) = tls::parse_client_hello(payload) {
                    let sni_str = ch.sni.as_deref().unwrap_or("-");

                    // 1. Check JA4 malware blocklist
                    if let Some(label) = engine.ja4_blocklist.get(&ch.ja4) {
                        let drop_it = engine.mode == IdsMode::Drop;
                        if drop_it {
                            should_drop = true;
                        }
                        alerts.push(NewAlert {
                            ts,
                            severity: "high".into(),
                            category: "ja4_malware".into(),
                            action: if drop_it { "dropped" } else { "alert" }.into(),
                            src_ip: src_ip.clone(),
                            dst_ip: dst_ip.clone(),
                            dst_port,
                            indicator: ch.ja4.clone(),
                            detail: format!("JA4 match '{}' (SNI={}, TLS {})", label, sni_str, ch.tls_version),
                        });
                    }

                    // 2. Check TLS SNI against blocked domains
                    if let Some(sni) = &ch.sni {
                        if engine.is_domain_blocked(sni) {
                            let drop_it = engine.mode == IdsMode::Drop;
                            if drop_it {
                                should_drop = true;
                            }
                            alerts.push(NewAlert {
                                ts,
                                severity: "high".into(),
                                category: "tls_sni_block".into(),
                                action: if drop_it { "dropped" } else { "alert" }.into(),
                                src_ip: src_ip.clone(),
                                dst_ip: dst_ip.clone(),
                                dst_port,
                                indicator: sni.clone(),
                                detail: format!("Blocked TLS SNI '{}' (JA4={})", sni, ch.ja4),
                            });
                        }
                    }

                    // 3. Evaluate Suricata TLS / JA4 subset rules
                    for r in &engine.suricata_rules {
                        if let Some(target_sni) = &r.tls_sni {
                            if let Some(sni) = &ch.sni {
                                if RuleEngine::domain_matches(sni, target_sni) {
                                    let drop_it = engine.mode == IdsMode::Drop || r.action == "drop";
                                    if drop_it && engine.mode == IdsMode::Drop {
                                        should_drop = true;
                                    }
                                    let eff_drop = engine.mode == IdsMode::Drop;
                                    alerts.push(NewAlert {
                                        ts,
                                        severity: "high".into(),
                                        category: "suricata_tls".into(),
                                        action: if eff_drop { "dropped" } else { "alert" }.into(),
                                        src_ip: src_ip.clone(),
                                        dst_ip: dst_ip.clone(),
                                        dst_port,
                                        indicator: format!("{} (JA4={})", sni, ch.ja4),
                                        detail: format!("[sid:{}] {}", r.sid, r.msg),
                                    });
                                }
                            }
                        }
                        if let Some(target_ja4) = &r.ja4_hash {
                            if ch.ja4 == *target_ja4 {
                                let eff_drop = engine.mode == IdsMode::Drop;
                                if eff_drop {
                                    should_drop = true;
                                }
                                alerts.push(NewAlert {
                                    ts,
                                    severity: "high".into(),
                                    category: "suricata_ja4".into(),
                                    action: if eff_drop { "dropped" } else { "alert" }.into(),
                                    src_ip: src_ip.clone(),
                                    dst_ip: dst_ip.clone(),
                                    dst_port,
                                    indicator: ch.ja4.clone(),
                                    detail: format!("[sid:{}] {}", r.sid, r.msg),
                                });
                            }
                        }
                    }
                }
            }
        }
        // UDP (17)
        17 if l4.len() >= 8 => {
            let dst_port = u16::from_be_bytes([l4[2], l4[3]]);
            let payload = &l4[8..];
            if dst_port == 53 {
                let parsed = dns_wire::parse_dns_query(payload);
                let dom_label = parsed
                    .as_ref()
                    .map(|q| q.domain.clone())
                    .unwrap_or_else(|| "udp/53".to_string());

                // 1. DNS-bypass detection (LAN -> external UDP/53 bypassing router dnsmasq)
                if engine.detect_dns_bypass {
                    let drop_it = engine.mode == IdsMode::Drop;
                    if drop_it {
                        should_drop = true;
                    }
                    alerts.push(NewAlert {
                        ts,
                        severity: "medium".into(),
                        category: "dns_bypass".into(),
                        action: if drop_it { "dropped" } else { "alert" }.into(),
                        src_ip: src_ip.clone(),
                        dst_ip: dst_ip.clone(),
                        dst_port,
                        indicator: dom_label.clone(),
                        detail: format!(
                            "Direct external DNS query to {}:53 bypassing router DNS",
                            dst_ip
                        ),
                    });
                }

                // 2. Suricata DNS query rules
                if let Some(q) = parsed {
                    for r in &engine.suricata_rules {
                        if let Some(target_dns) = &r.dns_query {
                            if RuleEngine::domain_matches(&q.domain, target_dns) {
                                let drop_it = engine.mode == IdsMode::Drop;
                                if drop_it {
                                    should_drop = true;
                                }
                                alerts.push(NewAlert {
                                    ts,
                                    severity: "high".into(),
                                    category: "suricata_dns".into(),
                                    action: if drop_it { "dropped" } else { "alert" }.into(),
                                    src_ip: src_ip.clone(),
                                    dst_ip: dst_ip.clone(),
                                    dst_port,
                                    indicator: q.domain.clone(),
                                    detail: format!("[sid:{}] {}", r.sid, r.msg),
                                });
                            }
                        }
                    }
                }
            }
        }
        _ => {}
    }

    InspectOutcome {
        verdict: if should_drop {
            PacketVerdict::Drop
        } else {
            PacketVerdict::Accept
        },
        alerts,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wrap_ipv4_udp(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
        let udp_len = (8 + payload.len()) as u16;
        let tot_len = 20 + udp_len;
        let mut pkt = vec![0u8; 20];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&tot_len.to_be_bytes());
        pkt[9] = 17;
        pkt[12..16].copy_from_slice(&src);
        pkt[16..20].copy_from_slice(&dst);
        pkt.extend_from_slice(&sport.to_be_bytes());
        pkt.extend_from_slice(&dport.to_be_bytes());
        pkt.extend_from_slice(&udp_len.to_be_bytes());
        pkt.extend_from_slice(&[0, 0]);
        pkt.extend_from_slice(payload);
        pkt
    }

    #[test]
    fn detects_and_drops_dns_bypass_by_mode() {
        let mut dns = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        dns.push(4);
        dns.extend_from_slice(b"evil");
        dns.push(4);
        dns.extend_from_slice(b"test");
        dns.push(0);
        dns.extend_from_slice(&[0, 1, 0, 1]);

        let pkt = wrap_ipv4_udp([10, 100, 0, 20], [8, 8, 8, 8], 55555, 53, &dns);

        let alert_engine = RuleEngine::new(true, IdsMode::Alert, 1, true, 12, vec![]);
        let r1 = inspect_ipv4_packet(&pkt, &alert_engine);
        assert_eq!(r1.verdict, PacketVerdict::Accept);
        assert_eq!(r1.alerts.len(), 1);
        assert_eq!(r1.alerts[0].category, "dns_bypass");

        let drop_engine = RuleEngine::new(true, IdsMode::Drop, 1, true, 12, vec![]);
        let r2 = inspect_ipv4_packet(&pkt, &drop_engine);
        assert_eq!(r2.verdict, PacketVerdict::Drop);
        assert_eq!(r2.alerts[0].action, "dropped");
    }
}
