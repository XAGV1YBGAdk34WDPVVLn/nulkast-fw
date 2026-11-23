use crate::config::{
    validate_domain, validate_ipv4, validate_ipv4_or_cidr, validate_mac, validate_proto,
    AllowedPort, FwConfig,
};
use crate::dns;
use crate::feeds;
use crate::inspect::{IdsMode, SharedRuleEngine};
use crate::nft;
use crate::shaper;
use crate::store::{
    now_unix, DbStats, NewAlert, NewAudit, NewDnsQuery, NewFlow, Store, StoreEvent, StoreWriter,
};
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path as AxumPath, Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{broadcast, Mutex};

const INDEX_HTML: &str = include_str!("../web/index.html");
const APP_CSS: &str = include_str!("../web/app.css");
const APP_JS: &str = include_str!("../web/app.js");

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum WsEvent {
    Flow(NewFlow),
    DnsQuery(NewDnsQuery),
    Alert(NewAlert),
    RuleChanged { action: String, target: String },
    FirewallApplied { rollback_token: Option<String> },
}

#[derive(Clone)]
pub struct AppState {
    pub config_path: PathBuf,
    pub state_dir: PathBuf,
    pub store: Arc<Store>,
    pub writer: StoreWriter,
    pub engine: SharedRuleEngine,
    pub events_tx: broadcast::Sender<WsEvent>,
    pub apply_lock: Arc<Mutex<()>>,
    pub dry_run: bool,
}

#[derive(Serialize)]
struct ApiError {
    error: String,
}

fn err_resp(status: StatusCode, msg: impl Into<String>) -> Response {
    (status, Json(ApiError { error: msg.into() })).into_response()
}

pub fn build_router(state: AppState) -> Router {
    Router::new()
        // Embedded zero-build Web UI
        .route("/", get(ui_index))
        .route("/app.css", get(ui_css))
        .route("/app.js", get(ui_js))
        // Strict async REST API v1
        .route("/api/v1/health", get(get_health))
        .route("/api/v1/status", get(get_status))
        .route("/api/v1/rules", get(get_rules))
        .route("/api/v1/rules/ips", post(post_block_ip))
        .route("/api/v1/rules/ips/*ip", delete(delete_block_ip))
        .route("/api/v1/rules/domains", post(post_block_domain))
        .route("/api/v1/rules/domains/:domain", delete(delete_block_domain))
        .route("/api/v1/rules/ports", post(post_allow_port))
        .route("/api/v1/rules/ports/:proto/:port", delete(delete_allow_port))
        .route("/api/v1/devices", get(get_devices))
        .route("/api/v1/devices/:mac/pause", post(post_pause_device))
        .route("/api/v1/devices/:mac/pause", delete(delete_pause_device))
        .route("/api/v1/flows", get(get_flows))
        .route("/api/v1/dns/queries", get(get_dns_queries))
        .route("/api/v1/dns/hosts", get(get_dns_hosts).post(post_dns_host))
        .route("/api/v1/dns/hosts/:domain", delete(delete_dns_host))
        .route("/api/v1/alerts", get(get_alerts))
        .route("/api/v1/ids/status", get(get_ids_status))
        .route("/api/v1/ids/mode", post(post_ids_mode))
        .route("/api/v1/feeds/import", post(post_feeds_import))
        .route("/api/v1/sqm", get(get_sqm).post(post_sqm))
        .route("/api/v1/audit", get(get_audit))
        .route("/api/v1/firewall/apply", post(post_firewall_apply))
        .route("/api/v1/firewall/confirm", post(post_firewall_confirm))
        .route("/api/v1/firewall/rollback", post(post_firewall_rollback))
        .route("/api/v1/ws/events", get(ws_events))
        .with_state(state)
}

async fn ui_index() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], INDEX_HTML)
}

async fn ui_css() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "text/css; charset=utf-8")], APP_CSS)
}

async fn ui_js() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "application/javascript; charset=utf-8")],
        APP_JS,
    )
}

#[derive(Serialize)]
struct HealthResp {
    status: &'static str,
    version: &'static str,
}

async fn get_health() -> Json<HealthResp> {
    Json(HealthResp {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
    })
}

#[derive(Serialize)]
struct StatusResp {
    wan: String,
    lan: Vec<String>,
    mgmt: Option<String>,
    blocked_ips: usize,
    blocked_domains: usize,
    paused_macs: usize,
    allowed_ports: usize,
    pending_rollback: Option<nft::PendingRollback>,
    db: DbStats,
}

async fn get_status(State(st): State<AppState>) -> Response {
    let cfg = match FwConfig::load(&st.config_path) {
        Ok(c) => c,
        Err(e) => return err_resp(StatusCode::INTERNAL_SERVER_ERROR, e),
    };
    let store = Arc::clone(&st.store);
    let db = match tokio::task::spawn_blocking(move || store.stats()).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return err_resp(StatusCode::INTERNAL_SERVER_ERROR, e),
        Err(e) => return err_resp(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    };

    Json(StatusResp {
        wan: cfg.interfaces.wan,
        lan: cfg.interfaces.lan,
        mgmt: cfg.interfaces.mgmt,
        blocked_ips: cfg.blocked_ips.len(),
        blocked_domains: cfg.blocked_domains.len(),
        paused_macs: cfg.paused_macs.len(),
        allowed_ports: cfg.allowed_ports.len(),
        pending_rollback: nft::read_pending_rollback(&st.state_dir),
        db,
    })
    .into_response()
}

#[derive(Serialize)]
struct RulesResp {
    blocked_ips: Vec<String>,
    blocked_domains: Vec<String>,
    paused_macs: Vec<String>,
    allowed_ports: Vec<AllowedPort>,
}

async fn get_rules(State(st): State<AppState>) -> Response {
    match FwConfig::load(&st.config_path) {
        Ok(cfg) => Json(RulesResp {
            blocked_ips: cfg.blocked_ips,
            blocked_domains: cfg.blocked_domains,
            paused_macs: cfg.paused_macs,
            allowed_ports: cfg.allowed_ports,
        })
        .into_response(),
        Err(e) => err_resp(StatusCode::INTERNAL_SERVER_ERROR, e),
    }
}

#[derive(Deserialize)]
struct IpReq {
    ip: String,
}

async fn apply_nft_and_save_good(st: &AppState, cfg: &FwConfig, apply_dns: bool) -> Result<(), String> {
    if st.dry_run {
        let _ = nft::render_ruleset(cfg)?;
        if apply_dns {
            let _ = dns::render_dnsmasq_conf(cfg, &st.state_dir)?;
            let _ = dns::render_sinkhole_conf(cfg)?;
        }
        return cfg.save(&nft::last_good_config_path(&st.state_dir));
    }
    let cfg_clone = cfg.clone();
    let state_dir = st.state_dir.clone();
    tokio::task::spawn_blocking(move || {
        let ruleset = nft::render_ruleset(&cfg_clone)?;
        nft::apply_ruleset(&ruleset, &state_dir)?;
        if apply_dns {
            dns::apply_dnsmasq(&cfg_clone, &state_dir)?;
        }
        cfg_clone.save(&nft::last_good_config_path(&state_dir))
    })
    .await
    .map_err(|e| e.to_string())?
}

async fn post_block_ip(State(st): State<AppState>, Json(req): Json<IpReq>) -> Response {
    if let Err(e) = validate_ipv4_or_cidr(&req.ip) {
        return err_resp(StatusCode::BAD_REQUEST, e);
    }
    let _guard = st.apply_lock.lock().await;
    let mut cfg = match FwConfig::load(&st.config_path) {
        Ok(c) => c,
        Err(e) => return err_resp(StatusCode::INTERNAL_SERVER_ERROR, e),
    };
    if !cfg.blocked_ips.contains(&req.ip) {
        cfg.blocked_ips.push(req.ip.clone());
    }
    if let Err(e) = cfg.save(&st.config_path) {
        return err_resp(StatusCode::INTERNAL_SERVER_ERROR, e);
    }
    if let Err(e) = apply_nft_and_save_good(&st, &cfg, false).await {
        return err_resp(StatusCode::INTERNAL_SERVER_ERROR, e);
    }
    record_mutation(&st, "block_ip", &req.ip, "blocked via REST API").await;
    (StatusCode::CREATED, Json(serde_json::json!({ "blocked_ip": req.ip }))).into_response()
}

async fn delete_block_ip(State(st): State<AppState>, AxumPath(ip): AxumPath<String>) -> Response {
    let ip = ip.trim_start_matches('/').to_string();
    let _guard = st.apply_lock.lock().await;
    let mut cfg = match FwConfig::load(&st.config_path) {
        Ok(c) => c,
        Err(e) => return err_resp(StatusCode::INTERNAL_SERVER_ERROR, e),
    };
    let before = cfg.blocked_ips.len();
    cfg.blocked_ips.retain(|x| x != &ip);
    if cfg.blocked_ips.len() == before {
        return err_resp(StatusCode::NOT_FOUND, format!("IP '{}' not in blocked_ips", ip));
    }
    if let Err(e) = cfg.save(&st.config_path) {
        return err_resp(StatusCode::INTERNAL_SERVER_ERROR, e);
    }
    if let Err(e) = apply_nft_and_save_good(&st, &cfg, false).await {
        return err_resp(StatusCode::INTERNAL_SERVER_ERROR, e);
    }
    record_mutation(&st, "unblock_ip", &ip, "unblocked via REST API").await;
    Json(serde_json::json!({ "unblocked_ip": ip })).into_response()
}

#[derive(Deserialize)]
struct DomainReq {
    domain: String,
}

async fn post_block_domain(State(st): State<AppState>, Json(req): Json<DomainReq>) -> Response {
    let d = req.domain.trim().to_lowercase();
    if let Err(e) = validate_domain(&d) {
        return err_resp(StatusCode::BAD_REQUEST, e);
    }
    let _guard = st.apply_lock.lock().await;
    let mut cfg = match FwConfig::load(&st.config_path) {
        Ok(c) => c,
        Err(e) => return err_resp(StatusCode::INTERNAL_SERVER_ERROR, e),
    };
    if !cfg.blocked_domains.contains(&d) {
        cfg.blocked_domains.push(d.clone());
    }
    if let Err(e) = cfg.save(&st.config_path) {
        return err_resp(StatusCode::INTERNAL_SERVER_ERROR, e);
    }
    if let Err(e) = apply_nft_and_save_good(&st, &cfg, true).await {
        return err_resp(StatusCode::INTERNAL_SERVER_ERROR, e);
    }
    if let Ok(mut eng) = st.engine.write() {
        eng.blocked_domains.insert(d.clone());
    }
    record_mutation(&st, "block_domain", &d, "sinkholed via REST API").await;
    (StatusCode::CREATED, Json(serde_json::json!({ "blocked_domain": d }))).into_response()
}

async fn delete_block_domain(
    State(st): State<AppState>,
    AxumPath(domain): AxumPath<String>,
) -> Response {
    let d = domain.to_lowercase();
    let _guard = st.apply_lock.lock().await;
    let mut cfg = match FwConfig::load(&st.config_path) {
        Ok(c) => c,
        Err(e) => return err_resp(StatusCode::INTERNAL_SERVER_ERROR, e),
    };
    let before = cfg.blocked_domains.len();
    cfg.blocked_domains.retain(|x| x.to_lowercase() != d);
    if cfg.blocked_domains.len() == before {
        return err_resp(StatusCode::NOT_FOUND, format!("domain '{}' not sinkholed", d));
    }
    if let Err(e) = cfg.save(&st.config_path) {
        return err_resp(StatusCode::INTERNAL_SERVER_ERROR, e);
    }
    if let Err(e) = apply_nft_and_save_good(&st, &cfg, true).await {
        return err_resp(StatusCode::INTERNAL_SERVER_ERROR, e);
    }
    if let Ok(mut eng) = st.engine.write() {
        eng.blocked_domains.remove(&d);
    }
    record_mutation(&st, "unblock_domain", &d, "removed from sinkhole via REST API").await;
    Json(serde_json::json!({ "unblocked_domain": d })).into_response()
}

#[derive(Deserialize)]
struct PortReq {
    proto: String,
    port: u16,
    comment: Option<String>,
}

async fn post_allow_port(State(st): State<AppState>, Json(req): Json<PortReq>) -> Response {
    let proto = req.proto.to_lowercase();
    if let Err(e) = validate_proto(&proto) {
        return err_resp(StatusCode::BAD_REQUEST, e);
    }
    if req.port == 0 {
        return err_resp(StatusCode::BAD_REQUEST, "port must be 1..=65535");
    }
    let _guard = st.apply_lock.lock().await;
    let mut cfg = match FwConfig::load(&st.config_path) {
        Ok(c) => c,
        Err(e) => return err_resp(StatusCode::INTERNAL_SERVER_ERROR, e),
    };
    if !cfg
        .allowed_ports
        .iter()
        .any(|p| p.proto == proto && p.port == req.port)
    {
        cfg.allowed_ports.push(AllowedPort {
            proto: proto.clone(),
            port: req.port,
            comment: req.comment.clone(),
        });
    }
    if let Err(e) = cfg.save(&st.config_path) {
        return err_resp(StatusCode::INTERNAL_SERVER_ERROR, e);
    }
    if let Err(e) = apply_nft_and_save_good(&st, &cfg, false).await {
        return err_resp(StatusCode::INTERNAL_SERVER_ERROR, e);
    }
    let target = format!("{}/{}", proto, req.port);
    record_mutation(&st, "allow_port", &target, "opened port via REST API").await;
    (
        StatusCode::CREATED,
        Json(serde_json::json!({ "proto": proto, "port": req.port })),
    )
        .into_response()
}

async fn delete_allow_port(
    State(st): State<AppState>,
    AxumPath((proto, port)): AxumPath<(String, u16)>,
) -> Response {
    let proto = proto.to_lowercase();
    let _guard = st.apply_lock.lock().await;
    let mut cfg = match FwConfig::load(&st.config_path) {
        Ok(c) => c,
        Err(e) => return err_resp(StatusCode::INTERNAL_SERVER_ERROR, e),
    };
    let before = cfg.allowed_ports.len();
    cfg.allowed_ports
        .retain(|p| !(p.proto == proto && p.port == port));
    if cfg.allowed_ports.len() == before {
        return err_resp(StatusCode::NOT_FOUND, format!("port {}/{} not open", proto, port));
    }
    if let Err(e) = cfg.save(&st.config_path) {
        return err_resp(StatusCode::INTERNAL_SERVER_ERROR, e);
    }
    if let Err(e) = apply_nft_and_save_good(&st, &cfg, false).await {
        return err_resp(StatusCode::INTERNAL_SERVER_ERROR, e);
    }
    let target = format!("{}/{}", proto, port);
    record_mutation(&st, "close_port", &target, "closed port via REST API").await;
    Json(serde_json::json!({ "closed": target })).into_response()
}

#[derive(Serialize)]
struct DeviceView {
    mac: String,
    ip: String,
    hostname: String,
    last_seen: u64,
    paused: bool,
}

async fn get_devices(State(st): State<AppState>) -> Response {
    let cfg = match FwConfig::load(&st.config_path) {
        Ok(c) => c,
        Err(e) => return err_resp(StatusCode::INTERNAL_SERVER_ERROR, e),
    };
    let paused: HashSet<String> = cfg.paused_macs.iter().map(|m| m.to_lowercase()).collect();
    let store = Arc::clone(&st.store);
    let stored = match tokio::task::spawn_blocking(move || store.list_devices(500)).await {
        Ok(Ok(d)) => d,
        Ok(Err(e)) => return err_resp(StatusCode::INTERNAL_SERVER_ERROR, e),
        Err(e) => return err_resp(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    };

    let mut by_mac: HashMap<String, DeviceView> = HashMap::new();
    for d in stored {
        let mac = d.mac.to_lowercase();
        by_mac.insert(
            mac.clone(),
            DeviceView {
                paused: paused.contains(&mac),
                mac,
                ip: d.ip,
                hostname: d.hostname,
                last_seen: d.last_seen,
            },
        );
    }
    for l in dns::read_leases(&st.state_dir) {
        let mac = l.mac.to_lowercase();
        by_mac.entry(mac.clone()).or_insert(DeviceView {
            paused: paused.contains(&mac),
            mac,
            ip: l.ip,
            hostname: l.hostname,
            last_seen: l.expires_unix,
        });
    }
    let mut list: Vec<DeviceView> = by_mac.into_values().collect();
    list.sort_by(|a, b| b.last_seen.cmp(&a.last_seen).then(a.ip.cmp(&b.ip)));
    Json(list).into_response()
}

async fn post_pause_device(State(st): State<AppState>, AxumPath(mac): AxumPath<String>) -> Response {
    let m = mac.to_lowercase();
    if let Err(e) = validate_mac(&m) {
        return err_resp(StatusCode::BAD_REQUEST, e);
    }
    let _guard = st.apply_lock.lock().await;
    let mut cfg = match FwConfig::load(&st.config_path) {
        Ok(c) => c,
        Err(e) => return err_resp(StatusCode::INTERNAL_SERVER_ERROR, e),
    };
    if !cfg.paused_macs.iter().any(|x| x.to_lowercase() == m) {
        cfg.paused_macs.push(m.clone());
    }
    if let Err(e) = cfg.save(&st.config_path) {
        return err_resp(StatusCode::INTERNAL_SERVER_ERROR, e);
    }
    if let Err(e) = apply_nft_and_save_good(&st, &cfg, false).await {
        return err_resp(StatusCode::INTERNAL_SERVER_ERROR, e);
    }
    record_mutation(&st, "pause_device", &m, "paused via REST API").await;
    Json(serde_json::json!({ "paused_mac": m })).into_response()
}

async fn delete_pause_device(
    State(st): State<AppState>,
    AxumPath(mac): AxumPath<String>,
) -> Response {
    let m = mac.to_lowercase();
    let _guard = st.apply_lock.lock().await;
    let mut cfg = match FwConfig::load(&st.config_path) {
        Ok(c) => c,
        Err(e) => return err_resp(StatusCode::INTERNAL_SERVER_ERROR, e),
    };
    let before = cfg.paused_macs.len();
    cfg.paused_macs.retain(|x| x.to_lowercase() != m);
    if cfg.paused_macs.len() == before {
        return err_resp(StatusCode::NOT_FOUND, format!("MAC '{}' is not paused", m));
    }
    if let Err(e) = cfg.save(&st.config_path) {
        return err_resp(StatusCode::INTERNAL_SERVER_ERROR, e);
    }
    if let Err(e) = apply_nft_and_save_good(&st, &cfg, false).await {
        return err_resp(StatusCode::INTERNAL_SERVER_ERROR, e);
    }
    record_mutation(&st, "unpause_device", &m, "unpaused via REST API").await;
    Json(serde_json::json!({ "unpaused_mac": m })).into_response()
}

#[derive(Deserialize)]
struct LimitQuery {
    limit: Option<usize>,
}

async fn get_flows(State(st): State<AppState>, Query(q): Query<LimitQuery>) -> Response {
    let limit = q.limit.unwrap_or(100).clamp(1, 1000);
    let store = Arc::clone(&st.store);
    match tokio::task::spawn_blocking(move || store.list_flows(limit)).await {
        Ok(Ok(rows)) => Json(rows).into_response(),
        Ok(Err(e)) => err_resp(StatusCode::INTERNAL_SERVER_ERROR, e),
        Err(e) => err_resp(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

async fn get_dns_queries(State(st): State<AppState>, Query(q): Query<LimitQuery>) -> Response {
    let limit = q.limit.unwrap_or(100).clamp(1, 1000);
    let store = Arc::clone(&st.store);
    match tokio::task::spawn_blocking(move || store.list_dns_queries(limit)).await {
        Ok(Ok(rows)) => Json(rows).into_response(),
        Ok(Err(e)) => err_resp(StatusCode::INTERNAL_SERVER_ERROR, e),
        Err(e) => err_resp(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

#[derive(Serialize, Deserialize)]
struct LocalHostEntry {
    domain: String,
    ip: String,
}

#[derive(Serialize)]
struct LocalHostsResp {
    local_domain: String,
    hosts: Vec<LocalHostEntry>,
}

async fn get_dns_hosts(State(st): State<AppState>) -> Response {
    match FwConfig::load(&st.config_path) {
        Ok(cfg) => Json(LocalHostsResp {
            local_domain: cfg.dhcp.local_domain,
            hosts: cfg
                .local_hosts
                .into_iter()
                .map(|(domain, ip)| LocalHostEntry { domain, ip })
                .collect(),
        })
        .into_response(),
        Err(e) => err_resp(StatusCode::INTERNAL_SERVER_ERROR, e),
    }
}

async fn post_dns_host(State(st): State<AppState>, Json(req): Json<LocalHostEntry>) -> Response {
    let domain = req.domain.trim().to_lowercase();
    let ip = req.ip.trim().to_string();
    if let Err(e) = validate_domain(&domain) {
        return err_resp(StatusCode::BAD_REQUEST, e);
    }
    if let Err(e) = validate_ipv4(&ip) {
        return err_resp(StatusCode::BAD_REQUEST, e);
    }
    let _guard = st.apply_lock.lock().await;
    let mut cfg = match FwConfig::load(&st.config_path) {
        Ok(c) => c,
        Err(e) => return err_resp(StatusCode::INTERNAL_SERVER_ERROR, e),
    };
    if let Some(existing) = cfg
        .local_hosts
        .iter_mut()
        .find(|(d, _)| d.to_lowercase() == domain)
    {
        existing.1 = ip.clone();
    } else {
        cfg.local_hosts.push((domain.clone(), ip.clone()));
    }
    if let Err(e) = cfg.save(&st.config_path) {
        return err_resp(StatusCode::INTERNAL_SERVER_ERROR, e);
    }
    if let Err(e) = apply_nft_and_save_good(&st, &cfg, true).await {
        return err_resp(StatusCode::INTERNAL_SERVER_ERROR, e);
    }
    record_mutation(&st, "set_dns_host", &domain, &format!("-> {}", ip)).await;
    (
        StatusCode::CREATED,
        Json(LocalHostEntry { domain, ip }),
    )
        .into_response()
}

async fn delete_dns_host(
    State(st): State<AppState>,
    AxumPath(domain): AxumPath<String>,
) -> Response {
    let d = domain.to_lowercase();
    let _guard = st.apply_lock.lock().await;
    let mut cfg = match FwConfig::load(&st.config_path) {
        Ok(c) => c,
        Err(e) => return err_resp(StatusCode::INTERNAL_SERVER_ERROR, e),
    };
    let before = cfg.local_hosts.len();
    cfg.local_hosts.retain(|(host, _)| host.to_lowercase() != d);
    if cfg.local_hosts.len() == before {
        return err_resp(StatusCode::NOT_FOUND, format!("local DNS host '{}' not found", d));
    }
    if let Err(e) = cfg.save(&st.config_path) {
        return err_resp(StatusCode::INTERNAL_SERVER_ERROR, e);
    }
    if let Err(e) = apply_nft_and_save_good(&st, &cfg, true).await {
        return err_resp(StatusCode::INTERNAL_SERVER_ERROR, e);
    }
    record_mutation(&st, "delete_dns_host", &d, "removed internal DNS record").await;
    Json(serde_json::json!({ "deleted_host": d })).into_response()
}

async fn get_alerts(State(st): State<AppState>, Query(q): Query<LimitQuery>) -> Response {
    let limit = q.limit.unwrap_or(100).clamp(1, 1000);
    let store = Arc::clone(&st.store);
    match tokio::task::spawn_blocking(move || store.list_alerts(limit)).await {
        Ok(Ok(rows)) => Json(rows).into_response(),
        Ok(Err(e)) => err_resp(StatusCode::INTERNAL_SERVER_ERROR, e),
        Err(e) => err_resp(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

async fn get_ids_status(State(st): State<AppState>) -> Response {
    match st.engine.read() {
        Ok(eng) => Json(eng.stats()).into_response(),
        Err(_) => err_resp(StatusCode::INTERNAL_SERVER_ERROR, "ids engine lock poisoned"),
    }
}

#[derive(Deserialize)]
struct IdsModeReq {
    mode: String,
}

async fn post_ids_mode(State(st): State<AppState>, Json(req): Json<IdsModeReq>) -> Response {
    let mode_str = req.mode.to_lowercase();
    if !matches!(mode_str.as_str(), "alert" | "drop") {
        return err_resp(
            StatusCode::BAD_REQUEST,
            "invalid mode (expected 'alert' or 'drop')",
        );
    }
    let mode = IdsMode::from_str(&mode_str);
    if let Ok(mut eng) = st.engine.write() {
        eng.mode = mode;
    }
    let _guard = st.apply_lock.lock().await;
    if let Ok(mut cfg) = FwConfig::load(&st.config_path) {
        cfg.ids.mode = mode_str.clone();
        let _ = cfg.save(&st.config_path);
    }
    record_mutation(&st, "set_ids_mode", &mode_str, "updated IDS/IPS mode via REST API").await;
    Json(serde_json::json!({ "mode": mode_str })).into_response()
}

#[derive(Deserialize)]
struct FeedImportReq {
    format: String, // "ip" | "domain" | "ja4" | "suricata"
    content: String,
    #[serde(default)]
    apply: bool,
}

async fn post_feeds_import(State(st): State<AppState>, Json(req): Json<FeedImportReq>) -> Response {
    let fmt = req.format.to_lowercase();
    match fmt.as_str() {
        "ip" => {
            let ips = feeds::parse_ip_feed(&req.content);
            let imported = ips.len();
            let _guard = st.apply_lock.lock().await;
            let mut cfg = match FwConfig::load(&st.config_path) {
                Ok(c) => c,
                Err(e) => return err_resp(StatusCode::INTERNAL_SERVER_ERROR, e),
            };
            let existing: HashSet<String> = cfg.blocked_ips.iter().cloned().collect();
            for ip in ips {
                if !existing.contains(&ip) {
                    cfg.blocked_ips.push(ip);
                }
            }
            if let Err(e) = cfg.save(&st.config_path) {
                return err_resp(StatusCode::INTERNAL_SERVER_ERROR, e);
            }
            if req.apply {
                if let Err(e) = apply_nft_and_save_good(&st, &cfg, false).await {
                    return err_resp(StatusCode::INTERNAL_SERVER_ERROR, e);
                }
            }
            record_mutation(&st, "import_feed", "ip", &format!("{} entries", imported)).await;
            Json(serde_json::json!({ "format": "ip", "imported": imported })).into_response()
        }
        "domain" => {
            let doms = feeds::parse_domain_feed(&req.content);
            let imported = doms.len();
            if let Ok(mut eng) = st.engine.write() {
                for d in &doms {
                    eng.blocked_domains.insert(d.clone());
                }
            }
            let _guard = st.apply_lock.lock().await;
            let mut cfg = match FwConfig::load(&st.config_path) {
                Ok(c) => c,
                Err(e) => return err_resp(StatusCode::INTERNAL_SERVER_ERROR, e),
            };
            let existing: HashSet<String> =
                cfg.blocked_domains.iter().map(|d| d.to_lowercase()).collect();
            for d in doms {
                if !existing.contains(&d) {
                    cfg.blocked_domains.push(d);
                }
            }
            if let Err(e) = cfg.save(&st.config_path) {
                return err_resp(StatusCode::INTERNAL_SERVER_ERROR, e);
            }
            if req.apply {
                if let Err(e) = apply_nft_and_save_good(&st, &cfg, true).await {
                    return err_resp(StatusCode::INTERNAL_SERVER_ERROR, e);
                }
            }
            record_mutation(&st, "import_feed", "domain", &format!("{} entries", imported)).await;
            Json(serde_json::json!({ "format": "domain", "imported": imported })).into_response()
        }
        "ja4" => {
            let ja4s = feeds::parse_ja4_feed(&req.content);
            let imported = ja4s.len();
            if let Ok(mut eng) = st.engine.write() {
                for (h, label) in ja4s {
                    eng.ja4_blocklist.insert(h, label);
                }
            }
            record_mutation(&st, "import_feed", "ja4", &format!("{} hashes", imported)).await;
            Json(serde_json::json!({ "format": "ja4", "imported": imported })).into_response()
        }
        "suricata" => {
            let parsed = feeds::parse_suricata_subset(&req.content);
            let imported = parsed.rules.len();
            let skipped = parsed.skipped_unsupported;
            if let Ok(mut eng) = st.engine.write() {
                eng.suricata_rules.extend(parsed.rules);
            }
            record_mutation(
                &st,
                "import_feed",
                "suricata",
                &format!("{} rules ({} skipped)", imported, skipped),
            )
            .await;
            Json(serde_json::json!({
                "format": "suricata",
                "imported": imported,
                "skipped_unsupported": skipped
            }))
            .into_response()
        }
        _ => err_resp(
            StatusCode::BAD_REQUEST,
            "invalid feed format (expected ip, domain, ja4, or suricata)",
        ),
    }
}

async fn get_sqm(State(st): State<AppState>) -> Response {
    let cfg = match FwConfig::load(&st.config_path) {
        Ok(c) => c,
        Err(e) => return err_resp(StatusCode::INTERNAL_SERVER_ERROR, e),
    };
    let status = tokio::task::spawn_blocking(move || shaper::read_status(&cfg))
        .await
        .unwrap_or_else(|_| shaper::SqmStatus {
            enabled: false,
            wan: String::new(),
            ifb_dev: String::new(),
            download_mbps: 0,
            upload_mbps: 0,
            overhead: String::new(),
            egress_qdisc: String::new(),
            ingress_qdisc: String::new(),
        });
    Json(status).into_response()
}

#[derive(Deserialize)]
struct SqmReq {
    enabled: bool,
    download_mbps: u32,
    upload_mbps: u32,
    overhead: Option<String>,
}

async fn post_sqm(State(st): State<AppState>, Json(req): Json<SqmReq>) -> Response {
    let _guard = st.apply_lock.lock().await;
    let mut cfg = match FwConfig::load(&st.config_path) {
        Ok(c) => c,
        Err(e) => return err_resp(StatusCode::INTERNAL_SERVER_ERROR, e),
    };
    cfg.sqm.enabled = req.enabled;
    cfg.sqm.download_mbps = req.download_mbps;
    cfg.sqm.upload_mbps = req.upload_mbps;
    if let Some(ov) = req.overhead {
        cfg.sqm.overhead = ov.to_lowercase();
    }
    if let Err(e) = cfg.validate() {
        return err_resp(StatusCode::BAD_REQUEST, e);
    }
    if let Err(e) = cfg.save(&st.config_path) {
        return err_resp(StatusCode::INTERNAL_SERVER_ERROR, e);
    }
    if !st.dry_run {
        let cfg_clone = cfg.clone();
        match tokio::task::spawn_blocking(move || shaper::apply_sqm(&cfg_clone)).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return err_resp(StatusCode::INTERNAL_SERVER_ERROR, e),
            Err(e) => return err_resp(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
        }
    }
    record_mutation(
        &st,
        "update_sqm",
        if cfg.sqm.enabled { "enabled" } else { "disabled" },
        &format!(
            "{}mbit/{}mbit ({})",
            cfg.sqm.download_mbps, cfg.sqm.upload_mbps, cfg.sqm.overhead
        ),
    )
    .await;
    Json(serde_json::json!({
        "enabled": cfg.sqm.enabled,
        "download_mbps": cfg.sqm.download_mbps,
        "upload_mbps": cfg.sqm.upload_mbps,
        "overhead": cfg.sqm.overhead
    }))
    .into_response()
}

async fn get_audit(State(st): State<AppState>, Query(q): Query<LimitQuery>) -> Response {
    let limit = q.limit.unwrap_or(100).clamp(1, 1000);
    let store = Arc::clone(&st.store);
    match tokio::task::spawn_blocking(move || store.list_audit_log(limit)).await {
        Ok(Ok(rows)) => Json(rows).into_response(),
        Ok(Err(e)) => err_resp(StatusCode::INTERNAL_SERVER_ERROR, e),
        Err(e) => err_resp(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

#[derive(Deserialize, Default)]
struct ApplyReq {
    rollback_secs: Option<u64>,
    skip_dns: Option<bool>,
}

async fn post_firewall_apply(
    State(st): State<AppState>,
    body: Option<Json<ApplyReq>>,
) -> Response {
    let req = body.map(|b| b.0).unwrap_or_default();
    let rollback_secs = req.rollback_secs.unwrap_or(60);
    let skip_dns = req.skip_dns.unwrap_or(false);

    let _guard = st.apply_lock.lock().await;
    let cfg = match FwConfig::load(&st.config_path) {
        Ok(c) => c,
        Err(e) => return err_resp(StatusCode::INTERNAL_SERVER_ERROR, e),
    };

    if st.dry_run {
        if let Err(e) = nft::render_ruleset(&cfg) {
            return err_resp(StatusCode::BAD_REQUEST, e);
        }
        let _ = st.events_tx.send(WsEvent::FirewallApplied {
            rollback_token: None,
        });
        return Json(serde_json::json!({ "applied": true, "dry_run": true })).into_response();
    }

    let last_good = nft::last_good_config_path(&st.state_dir);
    let cfg_clone = cfg.clone();
    let state_dir = st.state_dir.clone();
    let res = tokio::task::spawn_blocking(move || {
        let ruleset = nft::render_ruleset(&cfg_clone)?;
        nft::apply_ruleset(&ruleset, &state_dir)?;
        if !skip_dns {
            dns::apply_dnsmasq(&cfg_clone, &state_dir)?;
        }
        Ok::<(), String>(())
    })
    .await;

    match res {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return err_resp(StatusCode::INTERNAL_SERVER_ERROR, e),
        Err(e) => return err_resp(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }

    let pending = if rollback_secs > 0 && last_good.exists() {
        match nft::arm_rollback_watchdog(&st.config_path, &st.state_dir, rollback_secs) {
            Ok(p) => Some(p),
            Err(e) => return err_resp(StatusCode::INTERNAL_SERVER_ERROR, e),
        }
    } else {
        let _ = cfg.save(&last_good);
        let _ = nft::clear_pending_rollback(&st.state_dir);
        None
    };

    let token = pending.as_ref().map(|p| p.token.clone());
    let _ = st.events_tx.send(WsEvent::FirewallApplied {
        rollback_token: token.clone(),
    });
    record_mutation(&st, "firewall_apply", "ruleset", "applied via REST API").await;
    Json(serde_json::json!({ "applied": true, "pending_rollback": pending })).into_response()
}

async fn post_firewall_confirm(State(st): State<AppState>) -> Response {
    let _guard = st.apply_lock.lock().await;
    let cfg = match FwConfig::load(&st.config_path) {
        Ok(c) => c,
        Err(e) => return err_resp(StatusCode::INTERNAL_SERVER_ERROR, e),
    };
    let cleared = match nft::clear_pending_rollback(&st.state_dir) {
        Ok(c) => c,
        Err(e) => return err_resp(StatusCode::INTERNAL_SERVER_ERROR, e),
    };
    if let Err(e) = cfg.save(&nft::last_good_config_path(&st.state_dir)) {
        return err_resp(StatusCode::INTERNAL_SERVER_ERROR, e);
    }
    record_mutation(&st, "firewall_confirm", "ruleset", "confirmed via REST API").await;
    Json(serde_json::json!({ "confirmed": true, "watchdog_disarmed": cleared })).into_response()
}

async fn post_firewall_rollback(State(st): State<AppState>) -> Response {
    let _guard = st.apply_lock.lock().await;
    let last_good = nft::last_good_config_path(&st.state_dir);
    if !last_good.exists() {
        return err_resp(StatusCode::NOT_FOUND, "no last_good snapshot available");
    }
    let prev = match FwConfig::load(&last_good) {
        Ok(c) => c,
        Err(e) => return err_resp(StatusCode::INTERNAL_SERVER_ERROR, e),
    };
    if !st.dry_run {
        let prev_clone = prev.clone();
        let state_dir = st.state_dir.clone();
        let res = tokio::task::spawn_blocking(move || {
            let ruleset = nft::render_ruleset(&prev_clone)?;
            nft::apply_ruleset(&ruleset, &state_dir)?;
            dns::apply_dnsmasq(&prev_clone, &state_dir)
        })
        .await;
        match res {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return err_resp(StatusCode::INTERNAL_SERVER_ERROR, e),
            Err(e) => return err_resp(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
        }
    }
    let _ = prev.save(&st.config_path);
    let _ = nft::clear_pending_rollback(&st.state_dir);
    record_mutation(&st, "firewall_rollback", "ruleset", "rolled back via REST API").await;
    Json(serde_json::json!({ "rolled_back": true })).into_response()
}

async fn record_mutation(st: &AppState, action: &str, target: &str, detail: &str) {
    st.writer
        .send(StoreEvent::RecordAudit(NewAudit {
            ts: now_unix(),
            actor: "api".into(),
            action: action.into(),
            target: target.into(),
            detail: detail.into(),
        }))
        .await;
    let _ = st.events_tx.send(WsEvent::RuleChanged {
        action: action.into(),
        target: target.into(),
    });
}

async fn ws_events(ws: WebSocketUpgrade, State(st): State<AppState>) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_ws(socket, st.events_tx.subscribe()))
}

async fn handle_ws(mut socket: WebSocket, mut rx: broadcast::Receiver<WsEvent>) {
    while let Ok(ev) = rx.recv().await {
        if let Ok(json) = serde_json::to_string(&ev) {
            if socket.send(Message::Text(json)).await.is_err() {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Method, Request};
    use http_body_util::BodyExt;
    use std::time::Duration;
    use tower::ServiceExt;

    async fn test_app() -> (Router, AppState, PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "nulkast-fw-api-test-{}-{}",
            now_unix(),
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let cfg_path = dir.join("config.toml");
        FwConfig::default().save(&cfg_path).unwrap();

        let store = Arc::new(Store::open_in_memory().unwrap());
        let writer = StoreWriter::spawn(Arc::clone(&store), Duration::from_secs(60), 7);
        let engine = Arc::new(std::sync::RwLock::new(crate::inspect::RuleEngine::new(
            true,
            IdsMode::Alert,
            1,
            true,
            12,
            vec![],
        )));
        let (events_tx, _) = broadcast::channel(64);
        let state = AppState {
            config_path: cfg_path,
            state_dir: dir.clone(),
            store,
            writer,
            engine,
            events_tx,
            apply_lock: Arc::new(Mutex::new(())),
            dry_run: true,
        };
        let router = build_router(state.clone());
        (router, state, dir)
    }

    async fn json_body(resp: Response) -> serde_json::Value {
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn rest_api_crud_and_validation_contracts() {
        let (app, state, dir) = test_app().await;

        // 1. Health & UI root
        let resp = app
            .clone()
            .oneshot(Request::builder().uri("/api/v1/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(json_body(resp).await["status"], "ok");

        let ui = app
            .clone()
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(ui.status(), StatusCode::OK);

        // 2. Reject invalid IP (400 Bad Request)
        let bad = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/rules/ips")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"ip":"not-an-ip; rm -rf /"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(bad.status(), StatusCode::BAD_REQUEST);

        // 3. Block & unblock CIDR via REST
        let created = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/rules/ips")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"ip":"203.0.113.0/24"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(created.status(), StatusCode::CREATED);

        let rules = app
            .clone()
            .oneshot(Request::builder().uri("/api/v1/rules").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(json_body(rules).await["blocked_ips"][0], "203.0.113.0/24");

        let deleted = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::DELETE)
                    .uri("/api/v1/rules/ips/203.0.113.0/24")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(deleted.status(), StatusCode::OK);

        // 4. Block domain + pause device + audit trail
        let dom = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/rules/domains")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"domain":"ads.bad.test"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(dom.status(), StatusCode::CREATED);

        let pause = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/devices/02:42:ac:11:00:02/pause")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(pause.status(), StatusCode::OK);

        state.writer.flush().await;
        let audit = app
            .clone()
            .oneshot(Request::builder().uri("/api/v1/audit?limit=10").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(audit.status(), StatusCode::OK);
        let audit_json = json_body(audit).await;
        assert!(audit_json.as_array().unwrap().len() >= 4);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
