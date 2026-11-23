use crate::config::FwConfig;
use serde::Serialize;
use std::process::Command;

#[derive(Debug, Clone, Serialize)]
pub struct SqmStatus {
    pub enabled: bool,
    pub wan: String,
    pub ifb_dev: String,
    pub download_mbps: u32,
    pub upload_mbps: u32,
    pub overhead: String,
    pub egress_qdisc: String,
    pub ingress_qdisc: String,
}

/// Build the exact, deterministic `ip`/`tc` command sequence for DOCSIS CAKE SQM
/// (WAN egress + IFB ingress with `diffserv4`, `nat`, `dual-srchost`/`dual-dsthost`).
pub fn build_apply_commands(cfg: &FwConfig) -> Result<Vec<Vec<String>>, String> {
    cfg.validate()?;
    let wan = &cfg.interfaces.wan;
    let ifb = &cfg.sqm.ifb_dev;
    let ul = format!("{}mbit", cfg.sqm.upload_mbps);
    let dl = format!("{}mbit", cfg.sqm.download_mbps);
    let ov = &cfg.sqm.overhead;

    Ok(vec![
        // 1. Egress CAKE on WAN (eliminates cable upload bufferbloat)
        vec![
            "tc".into(),
            "qdisc".into(),
            "replace".into(),
            "dev".into(),
            wan.clone(),
            "root".into(),
            "cake".into(),
            "bandwidth".into(),
            ul,
            ov.clone(),
            "dual-srchost".into(),
            "nat".into(),
            "diffserv4".into(),
        ],
        // 2. Ensure IFB device exists and is up
        vec![
            "ip".into(),
            "link".into(),
            "set".into(),
            ifb.clone(),
            "up".into(),
        ],
        // 3. Attach ingress qdisc on WAN and redirect all ingress traffic to IFB
        vec![
            "tc".into(),
            "qdisc".into(),
            "replace".into(),
            "dev".into(),
            wan.clone(),
            "handle".into(),
            "ffff:".into(),
            "ingress".into(),
        ],
        vec![
            "tc".into(),
            "filter".into(),
            "replace".into(),
            "dev".into(),
            wan.clone(),
            "parent".into(),
            "ffff:".into(),
            "protocol".into(),
            "all".into(),
            "u32".into(),
            "match".into(),
            "u32".into(),
            "0".into(),
            "0".into(),
            "action".into(),
            "mirred".into(),
            "egress".into(),
            "redirect".into(),
            "dev".into(),
            ifb.clone(),
        ],
        // 4. Ingress CAKE on IFB
        vec![
            "tc".into(),
            "qdisc".into(),
            "replace".into(),
            "dev".into(),
            ifb.clone(),
            "root".into(),
            "cake".into(),
            "bandwidth".into(),
            dl,
            ov.clone(),
            "dual-dsthost".into(),
            "ingress".into(),
            "diffserv4".into(),
        ],
    ])
}

/// Apply DOCSIS CAKE SQM to WAN egress and IFB ingress (or disable if `cfg.sqm.enabled == false`).
pub fn apply_sqm(cfg: &FwConfig) -> Result<(), String> {
    cfg.validate()?;
    if !cfg.sqm.enabled {
        return disable_sqm(cfg);
    }

    // Best-effort modprobe + idempotent IFB creation
    let _ = Command::new("modprobe").arg("ifb").status();
    let _ = Command::new("modprobe").arg("sch_cake").status();
    let _ = Command::new("modprobe").arg("act_mirred").status();
    let _ = Command::new("ip")
        .args(["link", "add", &cfg.sqm.ifb_dev, "type", "ifb"])
        .output();

    for cmd in build_apply_commands(cfg)? {
        let out = Command::new(&cmd[0])
            .args(&cmd[1..])
            .output()
            .map_err(|e| format!("failed to execute `{}`: {}", cmd.join(" "), e))?;
        if !out.status.success() {
            return Err(format!(
                "command `{}` failed:\n{}",
                cmd.join(" "),
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
    }
    Ok(())
}

/// Cleanly remove SQM qdiscs from WAN and IFB device.
pub fn disable_sqm(cfg: &FwConfig) -> Result<(), String> {
    cfg.validate()?;
    let wan = &cfg.interfaces.wan;
    let ifb = &cfg.sqm.ifb_dev;
    let _ = Command::new("tc").args(["qdisc", "del", "dev", wan, "root"]).output();
    let _ = Command::new("tc").args(["qdisc", "del", "dev", wan, "ingress"]).output();
    let _ = Command::new("tc").args(["qdisc", "del", "dev", ifb, "root"]).output();
    let _ = Command::new("ip").args(["link", "del", ifb]).output();
    Ok(())
}

pub fn read_status(cfg: &FwConfig) -> SqmStatus {
    let wan = &cfg.interfaces.wan;
    let ifb = &cfg.sqm.ifb_dev;
    let egress_qdisc = Command::new("tc")
        .args(["-s", "qdisc", "show", "dev", wan])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    let ingress_qdisc = Command::new("tc")
        .args(["-s", "qdisc", "show", "dev", ifb])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();

    SqmStatus {
        enabled: cfg.sqm.enabled,
        wan: wan.clone(),
        ifb_dev: ifb.clone(),
        download_mbps: cfg.sqm.download_mbps,
        upload_mbps: cfg.sqm.upload_mbps,
        overhead: cfg.sqm.overhead.clone(),
        egress_qdisc,
        ingress_qdisc,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_docsis_cake_egress_and_ifb_ingress_commands() {
        let mut cfg = FwConfig::default();
        cfg.interfaces.wan = "wan0".into();
        cfg.sqm.enabled = true;
        cfg.sqm.download_mbps = 950;
        cfg.sqm.upload_mbps = 35;
        cfg.sqm.overhead = "docsis".into();
        cfg.sqm.ifb_dev = "ifb-dl".into();

        let cmds = build_apply_commands(&cfg).expect("must build commands");
        assert_eq!(cmds.len(), 5);
        let egress = cmds[0].join(" ");
        assert_eq!(
            egress,
            "tc qdisc replace dev wan0 root cake bandwidth 35mbit docsis dual-srchost nat diffserv4"
        );
        let ingress = cmds[4].join(" ");
        assert_eq!(
            ingress,
            "tc qdisc replace dev ifb-dl root cake bandwidth 950mbit docsis dual-dsthost ingress diffserv4"
        );
    }
}
