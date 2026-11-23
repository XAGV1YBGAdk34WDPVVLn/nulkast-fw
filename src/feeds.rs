use crate::config::{validate_domain, validate_ipv4_or_cidr};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SuricataRule {
    pub action: String, // "alert" or "drop"
    pub proto: String,  // "tls", "dns", "tcp", "udp", "ip"
    pub dst_port: Option<u16>,
    pub sid: u64,
    pub msg: String,
    pub classtype: Option<String>,
    pub tls_sni: Option<String>,
    pub dns_query: Option<String>,
    pub ja4_hash: Option<String>,
    pub nocase: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SuricataImportResult {
    pub rules: Vec<SuricataRule>,
    pub skipped_unsupported: usize,
}

/// Parse Spamhaus DROP / FireHOL / Abuse.ch Feodo IP & CIDR lists.
pub fn parse_ip_feed(content: &str) -> Vec<String> {
    let mut out = Vec::new();
    for raw in content.lines() {
        let line = raw
            .split('#')
            .next()
            .unwrap_or("")
            .split(';')
            .next()
            .unwrap_or("")
            .trim();
        if line.is_empty() {
            continue;
        }
        let token = line.split_whitespace().next().unwrap_or("");
        if validate_ipv4_or_cidr(token).is_ok() {
            out.push(token.to_string());
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Parse Hosts (`0.0.0.0 dom`), Adblock (`||dom^`), and plain domain lists (Hagezi/OISD/NulKast).
pub fn parse_domain_feed(content: &str) -> Vec<String> {
    let mut out = Vec::new();
    for raw in content.lines() {
        let line = raw.trim();
        if line.is_empty()
            || line.starts_with('#')
            || line.starts_with('!')
            || line.starts_with('[')
            || line.starts_with("@@")
        {
            continue;
        }
        let candidate = if let Some(rest) = line.strip_prefix("||") {
            rest.split('^').next().unwrap_or("").trim()
        } else {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 && (parts[0] == "0.0.0.0" || parts[0] == "127.0.0.1") {
                parts[1]
            } else {
                parts[0]
            }
        };
        let dom = candidate.to_lowercase();
        if dom != "localhost" && validate_domain(&dom).is_ok() {
            out.push(dom);
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Parse FoxIO JA4 / Abuse.ch SSLBL hash lists (CSV or plain `ja4_hash[,label]`).
pub fn parse_ja4_feed(content: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for raw in content.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut cols = line.splitn(2, [',', ' ', '\t']);
        let hash = cols.next().unwrap_or("").trim().to_lowercase();
        let label = cols
            .next()
            .unwrap_or("malicious_ja4")
            .trim()
            .trim_matches('"')
            .to_string();
        if is_valid_ja4(&hash) {
            out.push((
                hash,
                if label.is_empty() {
                    "malicious_ja4".to_string()
                } else {
                    label
                },
            ));
        }
    }
    out
}

pub fn is_valid_ja4(s: &str) -> bool {
    let parts: Vec<&str> = s.split('_').collect();
    parts.len() == 3
        && parts[0].len() == 10
        && parts[1].len() == 12
        && parts[2].len() == 12
        && parts[1].chars().all(|c| c.is_ascii_hexdigit())
        && parts[2].chars().all(|c| c.is_ascii_hexdigit())
}

/// Parse modern Suricata `.rules` subset (~12 high-value keywords).
/// Cleanly skips and counts rules using unsupported legacy keywords (e.g. `pcre`, `flowbits`, `byte_test`).
pub fn parse_suricata_subset(content: &str) -> SuricataImportResult {
    let mut res = SuricataImportResult::default();
    for raw in content.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        match parse_one_suricata_rule(line) {
            Some(r) => res.rules.push(r),
            None => res.skipped_unsupported += 1,
        }
    }
    res
}

fn parse_one_suricata_rule(line: &str) -> Option<SuricataRule> {
    let open = line.find('(')?;
    let close = line.rfind(')')?;
    if close <= open {
        return None;
    }
    let header: Vec<&str> = line[..open].split_whitespace().collect();
    if header.len() < 7 {
        return None;
    }
    let action = header[0].to_lowercase();
    if !matches!(action.as_str(), "alert" | "drop") {
        return None;
    }
    let proto = header[1].to_lowercase();
    if !matches!(proto.as_str(), "tls" | "dns" | "tcp" | "udp" | "ip") {
        return None;
    }
    let dst_port = header[6].parse::<u16>().ok();

    let opts = &line[open + 1..close];
    let mut sid: Option<u64> = None;
    let mut msg = String::new();
    let mut classtype = None;
    let mut tls_sni = None;
    let mut dns_query = None;
    let mut ja4_hash = None;
    let mut nocase = false;
    let mut pending_buffer: Option<&str> = None;

    for part in opts.split(';') {
        let p = part.trim();
        if p.is_empty() {
            continue;
        }
        let (k, v_opt) = match p.split_once(':') {
            Some((k, v)) => (k.trim(), Some(v.trim().trim_matches('"'))),
            None => (p, None),
        };
        match k {
            "msg" => msg = v_opt.unwrap_or("").to_string(),
            "sid" => sid = v_opt.and_then(|v| v.parse().ok()),
            "classtype" => classtype = v_opt.map(|s| s.to_string()),
            "nocase" => nocase = true,
            "tls.sni" => pending_buffer = Some("tls.sni"),
            "dns.query" => pending_buffer = Some("dns.query"),
            "ja4.hash" => pending_buffer = Some("ja4.hash"),
            "content" => {
                let val = v_opt?.to_lowercase();
                match pending_buffer {
                    Some("tls.sni") => tls_sni = Some(val),
                    Some("dns.query") => dns_query = Some(val),
                    Some("ja4.hash") => ja4_hash = Some(val),
                    _ => return None, // raw payload content without modern sticky buffer
                }
            }
            "flow" | "rev" | "metadata" | "bsize" | "dotprefix" | "endswith" => {}
            // Unsupported legacy keywords -> cleanly skip rule
            _ => return None,
        }
    }

    if tls_sni.is_none() && dns_query.is_none() && ja4_hash.is_none() {
        return None;
    }

    Some(SuricataRule {
        action,
        proto,
        dst_port,
        sid: sid.unwrap_or(0),
        msg: if msg.is_empty() {
            format!("Suricata rule sid:{}", sid.unwrap_or(0))
        } else {
            msg
        },
        classtype,
        tls_sni,
        dns_query,
        ja4_hash,
        nocase,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_all_four_threat_feed_formats() {
        let ips = parse_ip_feed(
            "; Spamhaus DROP\n203.0.113.0/24 ; SBL123\n# comment\n198.51.100.7\ninvalid-line\n",
        );
        assert_eq!(ips, vec!["198.51.100.7", "203.0.113.0/24"]);

        let doms = parse_domain_feed(
            "! Adblock list\n||ads.bad.test^\n0.0.0.0 tracker.bad.test\n@@||allow.test^\nplain.bad.test\n",
        );
        assert_eq!(
            doms,
            vec!["ads.bad.test", "plain.bad.test", "tracker.bad.test"]
        );

        let ja4s = parse_ja4_feed(
            "# SSLBL JA4\nt13d1516h2_8daaf6152771_e5627efa2ab1,CobaltStrike\nbad_hash\n",
        );
        assert_eq!(ja4s.len(), 1);
        assert_eq!(ja4s[0].1, "CobaltStrike");

        let suri = parse_suricata_subset(
            r#"
            drop tls $HOME_NET any -> $EXTERNAL_NET 443 (msg:"Block Evil SNI"; tls.sni; content:"evil.test"; nocase; sid:900001; rev:1;)
            alert dns any any -> any 53 (msg:"Bad DNS"; dns.query; content:"c2.bad.test"; sid:900002;)
            alert tcp any any -> any any (msg:"Legacy PCRE"; content:"foo"; pcre:"/bar/i"; sid:900003;)
            "#,
        );
        assert_eq!(suri.rules.len(), 2);
        assert_eq!(suri.skipped_unsupported, 1);
        assert_eq!(suri.rules[0].action, "drop");
        assert_eq!(suri.rules[0].tls_sni.as_deref(), Some("evil.test"));
    }
}
