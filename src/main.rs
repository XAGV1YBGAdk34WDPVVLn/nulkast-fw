use clap::{Parser, Subcommand};
use nulkast_fw::config::{
    validate_domain, validate_ipv4_or_cidr, validate_mac, FwConfig,
};
use nulkast_fw::dns;
use nulkast_fw::nft;
use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};
use std::process;
use std::time::Duration;

#[derive(Parser)]
#[command(name = "nulkast-fw", version, about = "Lean Debian Linux firewall & IDS/IPS core")]
struct Cli {
    /// Path to nulkast-fw TOML config file
    #[arg(long, default_value = "/etc/nulkast-fw/config.toml")]
    config: PathBuf,

    /// Directory for active rulesets, snapshots, and leases
    #[arg(long, default_value = "/var/lib/nulkast-fw")]
    state_dir: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Create a default configuration file
    Init {
        #[arg(long, default_value = "eth0")]
        wan: String,
        #[arg(long, default_value = "eth1")]
        lan: String,
    },
    /// Show firewall status and active rule counts
    Status {
        #[arg(long)]
        json: bool,
    },
    /// Print generated nftables or dnsmasq config without applying
    Render {
        #[arg(long)]
        dns: bool,
    },
    /// Validate and atomically apply nftables + dnsmasq (with dead-man rollback by default)
    Apply {
        #[arg(long, default_value_t = 60)]
        rollback_secs: u64,
        #[arg(long)]
        no_rollback: bool,
        #[arg(long)]
        skip_dns: bool,
    },
    /// Confirm pending apply and disarm dead-man rollback
    Confirm,
    /// Immediately revert to the last confirmed known-good snapshot
    Rollback {
        #[arg(long)]
        skip_dns: bool,
    },
    /// List DHCP device leases
    Devices {
        #[arg(long)]
        json: bool,
    },
    /// Add an IP or CIDR to blocked_ips and apply immediately
    BlockIp { ip: String },
    /// Remove an IP or CIDR from blocked_ips and apply immediately
    UnblockIp { ip: String },
    /// Add a domain to the DNS sinkhole and apply immediately
    BlockDomain { domain: String },
    /// Remove a domain from the DNS sinkhole and apply immediately
    UnblockDomain { domain: String },
    /// Pause internet access for a device MAC and apply immediately
    PauseDevice { mac: String },
    /// Unpause internet access for a device MAC and apply immediately
    UnpauseDevice { mac: String },
    /// Internal detached rollback watchdog
    #[command(hide = true)]
    Watchdog {
        #[arg(long)]
        seconds: u64,
        #[arg(long)]
        token: String,
    },
}

#[derive(Serialize)]
struct StatusReport {
    config_path: String,
    wan: String,
    lan: Vec<String>,
    mgmt: Option<String>,
    blocked_ips: usize,
    blocked_domains: usize,
    paused_macs: usize,
    allowed_ports: usize,
    pending_rollback: Option<nft::PendingRollback>,
}

fn apply_all(
    cfg: &FwConfig,
    state_dir: &Path,
    skip_dns: bool,
) -> Result<(), String> {
    let ruleset = nft::render_ruleset(cfg)?;
    nft::apply_ruleset(&ruleset, state_dir)?;
    if !skip_dns {
        dns::apply_dnsmasq(cfg, state_dir)?;
    }
    Ok(())
}

fn save_last_good(cfg: &FwConfig, state_dir: &Path) -> Result<(), String> {
    cfg.save(&nft::last_good_config_path(state_dir))
}

fn run(cli: Cli) -> Result<(), String> {
    match cli.command {
        Commands::Init { wan, lan } => {
            let mut cfg = FwConfig::default();
            cfg.interfaces.wan = wan;
            cfg.interfaces.lan = vec![lan];
            cfg.save(&cli.config)?;
            println!("Initialized config at {}", cli.config.display());
        }
        Commands::Status { json } => {
            let cfg = FwConfig::load(&cli.config)?;
            let report = StatusReport {
                config_path: cli.config.display().to_string(),
                wan: cfg.interfaces.wan,
                lan: cfg.interfaces.lan,
                mgmt: cfg.interfaces.mgmt,
                blocked_ips: cfg.blocked_ips.len(),
                blocked_domains: cfg.blocked_domains.len(),
                paused_macs: cfg.paused_macs.len(),
                allowed_ports: cfg.allowed_ports.len(),
                pending_rollback: nft::read_pending_rollback(&cli.state_dir),
            };
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?
                );
            } else {
                println!("NulKast-FW Status");
                println!("  WAN:             {}", report.wan);
                println!("  LAN:             {}", report.lan.join(", "));
                println!(
                    "  MGMT:            {}",
                    report.mgmt.as_deref().unwrap_or("-")
                );
                println!("  Blocked IPs:     {}", report.blocked_ips);
                println!("  Blocked Domains: {}", report.blocked_domains);
                println!("  Paused MACs:     {}", report.paused_macs);
                println!("  Allowed Ports:   {}", report.allowed_ports);
                if let Some(rb) = report.pending_rollback {
                    println!(
                        "  Pending Rollback: token={} (expires unix {})",
                        rb.token, rb.expires_at_unix
                    );
                }
            }
        }
        Commands::Render { dns: render_dns } => {
            let cfg = FwConfig::load(&cli.config)?;
            if render_dns {
                println!("{}", dns::render_dnsmasq_conf(&cfg, &cli.state_dir)?);
                println!("{}", dns::render_sinkhole_conf(&cfg)?);
            } else {
                println!("{}", nft::render_ruleset(&cfg)?);
            }
        }
        Commands::Apply {
            rollback_secs,
            no_rollback,
            skip_dns,
        } => {
            let cfg = FwConfig::load(&cli.config)?;
            let last_good = nft::last_good_config_path(&cli.state_dir);

            if no_rollback || rollback_secs == 0 || !last_good.exists() {
                apply_all(&cfg, &cli.state_dir, skip_dns)?;
                save_last_good(&cfg, &cli.state_dir)?;
                let _ = nft::clear_pending_rollback(&cli.state_dir);
                println!("Applied and committed (last_good updated).");
            } else {
                apply_all(&cfg, &cli.state_dir, skip_dns)?;
                let pending = nft::arm_rollback_watchdog(&cli.config, &cli.state_dir, rollback_secs)?;
                println!(
                    "Applied with {}s dead-man rollback (token {}). Run `nulkast-fw confirm` to keep.",
                    rollback_secs, pending.token
                );
            }
        }
        Commands::Confirm => {
            let cfg = FwConfig::load(&cli.config)?;
            let cleared = nft::clear_pending_rollback(&cli.state_dir)?;
            save_last_good(&cfg, &cli.state_dir)?;
            if cleared {
                println!("Confirmed! Rollback watchdog disarmed and last_good updated.");
            } else {
                println!("No pending rollback; last_good refreshed.");
            }
        }
        Commands::Rollback { skip_dns } => {
            let last_good = nft::last_good_config_path(&cli.state_dir);
            if !last_good.exists() {
                return Err(format!("no last_good snapshot found at {}", last_good.display()));
            }
            let prev = FwConfig::load(&last_good)?;
            apply_all(&prev, &cli.state_dir, skip_dns)?;
            prev.save(&cli.config)?;
            let _ = nft::clear_pending_rollback(&cli.state_dir);
            println!("Rolled back to last_good snapshot.");
        }
        Commands::Devices { json } => {
            let leases = dns::read_leases(&cli.state_dir);
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&leases).map_err(|e| e.to_string())?
                );
            } else if leases.is_empty() {
                println!("No active DHCP leases.");
            } else {
                for l in leases {
                    println!("{:<15}  {:<17}  {}", l.ip, l.mac, l.hostname);
                }
            }
        }
        Commands::BlockIp { ip } => {
            validate_ipv4_or_cidr(&ip)?;
            let mut cfg = FwConfig::load(&cli.config)?;
            if !cfg.blocked_ips.contains(&ip) {
                cfg.blocked_ips.push(ip.clone());
            }
            cfg.save(&cli.config)?;
            apply_all(&cfg, &cli.state_dir, true)?;
            save_last_good(&cfg, &cli.state_dir)?;
            println!("Blocked IP {}", ip);
        }
        Commands::UnblockIp { ip } => {
            let mut cfg = FwConfig::load(&cli.config)?;
            cfg.blocked_ips.retain(|x| x != &ip);
            cfg.save(&cli.config)?;
            apply_all(&cfg, &cli.state_dir, true)?;
            save_last_good(&cfg, &cli.state_dir)?;
            println!("Unblocked IP {}", ip);
        }
        Commands::BlockDomain { domain } => {
            let d = domain.to_lowercase();
            validate_domain(&d)?;
            let mut cfg = FwConfig::load(&cli.config)?;
            if !cfg.blocked_domains.contains(&d) {
                cfg.blocked_domains.push(d.clone());
            }
            cfg.save(&cli.config)?;
            dns::apply_dnsmasq(&cfg, &cli.state_dir)?;
            save_last_good(&cfg, &cli.state_dir)?;
            println!("Sinkholed domain {}", d);
        }
        Commands::UnblockDomain { domain } => {
            let d = domain.to_lowercase();
            let mut cfg = FwConfig::load(&cli.config)?;
            cfg.blocked_domains.retain(|x| x != &d);
            cfg.save(&cli.config)?;
            dns::apply_dnsmasq(&cfg, &cli.state_dir)?;
            save_last_good(&cfg, &cli.state_dir)?;
            println!("Removed domain {} from sinkhole", d);
        }
        Commands::PauseDevice { mac } => {
            let m = mac.to_lowercase();
            validate_mac(&m)?;
            let mut cfg = FwConfig::load(&cli.config)?;
            if !cfg.paused_macs.contains(&m) {
                cfg.paused_macs.push(m.clone());
            }
            cfg.save(&cli.config)?;
            apply_all(&cfg, &cli.state_dir, true)?;
            save_last_good(&cfg, &cli.state_dir)?;
            println!("Paused device {}", m);
        }
        Commands::UnpauseDevice { mac } => {
            let m = mac.to_lowercase();
            let mut cfg = FwConfig::load(&cli.config)?;
            cfg.paused_macs.retain(|x| x != &m);
            cfg.save(&cli.config)?;
            apply_all(&cfg, &cli.state_dir, true)?;
            save_last_good(&cfg, &cli.state_dir)?;
            println!("Unpaused device {}", m);
        }
        Commands::Watchdog { seconds, token } => {
            std::thread::sleep(Duration::from_secs(seconds));
            if let Some(pending) = nft::read_pending_rollback(&cli.state_dir) {
                if pending.token == token {
                    let prev_path = PathBuf::from(&pending.previous_config_path);
                    if prev_path.exists() {
                        if let Ok(prev) = FwConfig::load(&prev_path) {
                            let _ = apply_all(&prev, &cli.state_dir, false);
                            let _ = prev.save(&cli.config);
                        }
                    }
                    let _ = fs::remove_file(nft::pending_rollback_path(&cli.state_dir));
                }
            }
        }
    }
    Ok(())
}

fn main() {
    let cli = Cli::parse();
    if let Err(err) = run(cli) {
        eprintln!("error: {}", err);
        process::exit(1);
    }
}
