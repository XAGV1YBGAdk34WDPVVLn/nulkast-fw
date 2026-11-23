use serde::{Deserialize, Serialize};
use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InterfacesConfig {
    pub wan: String,
    pub lan: Vec<String>,
    pub mgmt: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DhcpConfig {
    pub enabled: bool,
    pub range_start: String,
    pub range_end: String,
    pub lease_time: String,
    pub upstream_dns: Vec<String>,
    pub local_domain: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AllowedPort {
    pub proto: String,
    pub port: u16,
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StaticLease {
    pub mac: String,
    pub ip: String,
    pub hostname: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IdsConfig {
    pub enabled: bool,
    pub mode: String, // "alert" or "drop"
    pub queues: u16,
    pub detect_dns_bypass: bool,
    pub port_scan_threshold: u16,
}

impl Default for IdsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: "alert".to_string(),
            queues: 4,
            detect_dns_bypass: true,
            port_scan_threshold: 12,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FwConfig {
    pub interfaces: InterfacesConfig,
    pub dhcp: DhcpConfig,
    #[serde(default)]
    pub ids: IdsConfig,
    #[serde(default)]
    pub blocked_ips: Vec<String>,
    #[serde(default)]
    pub blocked_domains: Vec<String>,
    #[serde(default)]
    pub paused_macs: Vec<String>,
    #[serde(default)]
    pub allowed_ports: Vec<AllowedPort>,
    #[serde(default)]
    pub static_leases: Vec<StaticLease>,
    #[serde(default)]
    pub local_hosts: Vec<(String, String)>,
}

impl Default for FwConfig {
    fn default() -> Self {
        Self {
            interfaces: InterfacesConfig {
                wan: "eth0".to_string(),
                lan: vec!["eth1".to_string()],
                mgmt: None,
            },
            dhcp: DhcpConfig {
                enabled: false,
                range_start: "10.100.0.50".to_string(),
                range_end: "10.100.0.200".to_string(),
                lease_time: "12h".to_string(),
                upstream_dns: vec!["1.1.1.1".to_string(), "9.9.9.9".to_string()],
                local_domain: "lan".to_string(),
            },
            ids: IdsConfig::default(),
            blocked_ips: Vec::new(),
            blocked_domains: Vec::new(),
            paused_macs: Vec::new(),
            allowed_ports: Vec::new(),
            static_leases: Vec::new(),
            local_hosts: Vec::new(),
        }
    }
}

impl FwConfig {
    pub fn load(path: &Path) -> Result<Self, String> {
        let raw = fs::read_to_string(path)
            .map_err(|e| format!("failed to read config {}: {}", path.display(), e))?;
        let cfg: Self = toml::from_str(&raw)
            .map_err(|e| format!("failed to parse TOML {}: {}", path.display(), e))?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        self.validate()?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("failed to create dir {}: {}", parent.display(), e))?;
        }
        let body = toml::to_string_pretty(self)
            .map_err(|e| format!("failed to serialize config: {}", e))?;
        let tmp = path.with_extension("toml.tmp");
        fs::write(&tmp, body)
            .map_err(|e| format!("failed to write temp config {}: {}", tmp.display(), e))?;
        fs::rename(&tmp, path)
            .map_err(|e| format!("failed to atomically replace {}: {}", path.display(), e))?;
        Ok(())
    }

    pub fn validate(&self) -> Result<(), String> {
        validate_iface(&self.interfaces.wan)?;
        if self.interfaces.lan.is_empty() {
            return Err("interfaces.lan must contain at least one interface".into());
        }
        for iface in &self.interfaces.lan {
            validate_iface(iface)?;
            if iface == &self.interfaces.wan {
                return Err(format!("interface '{}' cannot be both WAN and LAN", iface));
            }
        }
        if let Some(mgmt) = &self.interfaces.mgmt {
            validate_iface(mgmt)?;
        }
        for ip in &self.blocked_ips {
            validate_ipv4_or_cidr(ip)?;
        }
        for dom in &self.blocked_domains {
            validate_domain(dom)?;
        }
        for mac in &self.paused_macs {
            validate_mac(mac)?;
        }
        for ap in &self.allowed_ports {
            validate_proto(&ap.proto)?;
            if ap.port == 0 {
                return Err("allowed_ports port must be 1..=65535".into());
            }
        }
        for dns in &self.dhcp.upstream_dns {
            validate_ipv4(dns)?;
        }
        for lease in &self.static_leases {
            validate_mac(&lease.mac)?;
            validate_ipv4(&lease.ip)?;
            validate_domain(&lease.hostname)?;
        }
        for (domain, ip) in &self.local_hosts {
            validate_domain(domain)?;
            validate_ipv4(ip)?;
        }
        if !matches!(self.ids.mode.as_str(), "alert" | "drop") {
            return Err(format!(
                "invalid ids.mode '{}' (expected 'alert' or 'drop')",
                self.ids.mode
            ));
        }
        if self.ids.queues == 0 || self.ids.queues > 16 {
            return Err("ids.queues must be 1..=16".into());
        }
        Ok(())
    }
}

pub fn validate_iface(name: &str) -> Result<(), String> {
    if name.is_empty() || name.len() > 15 {
        return Err(format!("invalid interface name '{}': length must be 1..=15", name));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
    {
        return Err(format!("invalid interface name '{}': illegal character", name));
    }
    Ok(())
}

pub fn validate_ipv4(s: &str) -> Result<(), String> {
    s.parse::<Ipv4Addr>()
        .map(|_| ())
        .map_err(|_| format!("invalid IPv4 address '{}'", s))
}

pub fn validate_ipv4_or_cidr(s: &str) -> Result<(), String> {
    if let Some((ip_part, prefix_part)) = s.split_once('/') {
        validate_ipv4(ip_part)?;
        let prefix: u8 = prefix_part
            .parse()
            .map_err(|_| format!("invalid CIDR prefix in '{}'", s))?;
        if prefix > 32 {
            return Err(format!("CIDR prefix out of range (0..=32) in '{}'", s));
        }
        Ok(())
    } else {
        validate_ipv4(s)
    }
}

pub fn validate_mac(s: &str) -> Result<(), String> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6
        || !parts
            .iter()
            .all(|p| p.len() == 2 && p.chars().all(|c| c.is_ascii_hexdigit()))
    {
        return Err(format!(
            "invalid MAC address '{}' (expected aa:bb:cc:dd:ee:ff)",
            s
        ));
    }
    Ok(())
}

pub fn validate_domain(s: &str) -> Result<(), String> {
    if s.is_empty() || s.len() > 253 || s.starts_with('.') || s.ends_with('.') {
        return Err(format!("invalid domain '{}'", s));
    }
    for label in s.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-')
        {
            return Err(format!("invalid domain label '{}' in '{}'", label, s));
        }
    }
    Ok(())
}

pub fn validate_proto(s: &str) -> Result<(), String> {
    match s {
        "tcp" | "udp" => Ok(()),
        _ => Err(format!("invalid protocol '{}' (expected tcp or udp)", s)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_valid() {
        assert!(FwConfig::default().validate().is_ok());
    }

    #[test]
    fn rejects_command_injection_inputs() {
        assert!(validate_iface("eth0; rm -rf /").is_err());
        assert!(validate_ipv4_or_cidr("1.2.3.4; drop").is_err());
        assert!(validate_ipv4_or_cidr("10.0.0.0/33").is_err());
        assert!(validate_mac("aa:bb:cc:dd:ee:gg").is_err());
        assert!(validate_domain("bad.test/0.0.0.0\nserver=1.2.3.4").is_err());
        assert!(validate_domain("-leading.test").is_err());
    }

    #[test]
    fn accepts_valid_network_inputs() {
        assert!(validate_iface("enp1s0").is_ok());
        assert!(validate_ipv4_or_cidr("10.200.0.2").is_ok());
        assert!(validate_ipv4_or_cidr("192.168.1.0/24").is_ok());
        assert!(validate_mac("02:42:ac:11:00:02").is_ok());
        assert!(validate_domain("ads.example-site.test").is_ok());
    }
}
