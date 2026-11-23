use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{mpsc, oneshot};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceRecord {
    pub mac: String,
    pub ip: String,
    pub hostname: String,
    pub first_seen: u64,
    pub last_seen: u64,
    pub bytes_tx: u64,
    pub bytes_rx: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowRecord {
    pub id: i64,
    pub ts: u64,
    pub proto: String,
    pub src_ip: String,
    pub src_port: u16,
    pub dst_ip: String,
    pub dst_port: u16,
    pub bytes_orig: u64,
    pub bytes_reply: u64,
    pub state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewFlow {
    pub ts: u64,
    pub proto: String,
    pub src_ip: String,
    pub src_port: u16,
    pub dst_ip: String,
    pub dst_port: u16,
    pub bytes_orig: u64,
    pub bytes_reply: u64,
    pub state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsQueryRecord {
    pub id: i64,
    pub ts: u64,
    pub client_ip: String,
    pub domain: String,
    pub qtype: String,
    pub action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewDnsQuery {
    pub ts: u64,
    pub client_ip: String,
    pub domain: String,
    pub qtype: String,
    pub action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    pub id: i64,
    pub ts: u64,
    pub actor: String,
    pub action: String,
    pub target: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewAudit {
    pub ts: u64,
    pub actor: String,
    pub action: String,
    pub target: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRecord {
    pub id: i64,
    pub ts: u64,
    pub severity: String,
    pub category: String,
    pub action: String,
    pub src_ip: String,
    pub dst_ip: String,
    pub dst_port: u16,
    pub indicator: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewAlert {
    pub ts: u64,
    pub severity: String,
    pub category: String,
    pub action: String,
    pub src_ip: String,
    pub dst_ip: String,
    pub dst_port: u16,
    pub indicator: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbStats {
    pub devices_count: u64,
    pub flows_count: u64,
    pub dns_queries_count: u64,
    pub alerts_count: u64,
    pub audit_count: u64,
    pub db_size_bytes: u64,
}

#[derive(Debug)]
pub enum StoreEvent {
    UpsertDevice {
        mac: String,
        ip: String,
        hostname: String,
        ts: u64,
    },
    RecordFlow(NewFlow),
    RecordDnsQuery(NewDnsQuery),
    RecordAlert(NewAlert),
    RecordAudit(NewAudit),
    Prune {
        flow_dns_cutoff_ts: u64,
        audit_cutoff_ts: u64,
    },
    Flush(oneshot::Sender<()>),
}

pub struct Store {
    path: PathBuf,
    conn: Mutex<Connection>,
}

impl Store {
    pub fn open(path: &Path) -> Result<Self, String> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("failed to create db dir {}: {}", parent.display(), e))?;
        }
        let conn = Connection::open(path)
            .map_err(|e| format!("failed to open sqlite db {}: {}", path.display(), e))?;
        Self::init_connection(&conn)?;
        Ok(Self {
            path: path.to_path_buf(),
            conn: Mutex::new(conn),
        })
    }

    pub fn open_in_memory() -> Result<Self, String> {
        let conn = Connection::open_in_memory()
            .map_err(|e| format!("failed to open in-memory sqlite: {}", e))?;
        Self::init_connection(&conn)?;
        Ok(Self {
            path: PathBuf::from(":memory:"),
            conn: Mutex::new(conn),
        })
    }

    fn init_connection(conn: &Connection) -> Result<(), String> {
        conn.execute_batch(
            r#"
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = NORMAL;
            PRAGMA foreign_keys = ON;
            PRAGMA busy_timeout = 5000;
            PRAGMA temp_store = MEMORY;

            CREATE TABLE IF NOT EXISTS devices (
                mac TEXT PRIMARY KEY,
                ip TEXT NOT NULL,
                hostname TEXT NOT NULL,
                first_seen INTEGER NOT NULL,
                last_seen INTEGER NOT NULL,
                bytes_tx INTEGER NOT NULL DEFAULT 0,
                bytes_rx INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS flows (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts INTEGER NOT NULL,
                proto TEXT NOT NULL,
                src_ip TEXT NOT NULL,
                src_port INTEGER NOT NULL,
                dst_ip TEXT NOT NULL,
                dst_port INTEGER NOT NULL,
                bytes_orig INTEGER NOT NULL,
                bytes_reply INTEGER NOT NULL,
                state TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_flows_ts ON flows(ts DESC);

            CREATE TABLE IF NOT EXISTS dns_queries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts INTEGER NOT NULL,
                client_ip TEXT NOT NULL,
                domain TEXT NOT NULL,
                qtype TEXT NOT NULL,
                action TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_dns_ts ON dns_queries(ts DESC);
            CREATE INDEX IF NOT EXISTS idx_dns_domain ON dns_queries(domain);

            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts INTEGER NOT NULL,
                severity TEXT NOT NULL,
                category TEXT NOT NULL,
                action TEXT NOT NULL,
                src_ip TEXT NOT NULL,
                dst_ip TEXT NOT NULL,
                dst_port INTEGER NOT NULL,
                indicator TEXT NOT NULL,
                detail TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts DESC);

            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts INTEGER NOT NULL,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                target TEXT NOT NULL,
                detail TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts DESC);
            "#,
        )
        .map_err(|e| format!("failed to initialize sqlite schema: {}", e))?;
        Ok(())
    }

    /// Commit a batch of events inside a single SQLite transaction (minimizes SSD write amp).
    pub fn apply_batch(&self, events: &[StoreEvent]) -> Result<(), String> {
        if events.is_empty() {
            return Ok(());
        }
        let mut conn = self.conn.lock().map_err(|_| "store mutex poisoned".to_string())?;
        let tx = conn
            .transaction()
            .map_err(|e| format!("failed to begin sqlite tx: {}", e))?;

        for ev in events {
            match ev {
                StoreEvent::UpsertDevice {
                    mac,
                    ip,
                    hostname,
                    ts,
                } => {
                    tx.execute(
                        r#"
                        INSERT INTO devices (mac, ip, hostname, first_seen, last_seen)
                        VALUES (?1, ?2, ?3, ?4, ?4)
                        ON CONFLICT(mac) DO UPDATE SET
                            ip = excluded.ip,
                            hostname = CASE
                                WHEN excluded.hostname != '' AND excluded.hostname != '*' THEN excluded.hostname
                                ELSE devices.hostname
                            END,
                            last_seen = excluded.last_seen
                        "#,
                        params![mac.to_lowercase(), ip, hostname, *ts as i64],
                    )
                    .map_err(|e| format!("upsert device failed: {}", e))?;
                }
                StoreEvent::RecordFlow(f) => {
                    tx.execute(
                        r#"
                        INSERT INTO flows (ts, proto, src_ip, src_port, dst_ip, dst_port, bytes_orig, bytes_reply, state)
                        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                        "#,
                        params![
                            f.ts as i64,
                            f.proto,
                            f.src_ip,
                            f.src_port as i64,
                            f.dst_ip,
                            f.dst_port as i64,
                            f.bytes_orig as i64,
                            f.bytes_reply as i64,
                            f.state
                        ],
                    )
                    .map_err(|e| format!("insert flow failed: {}", e))?;
                }
                StoreEvent::RecordDnsQuery(q) => {
                    tx.execute(
                        r#"
                        INSERT INTO dns_queries (ts, client_ip, domain, qtype, action)
                        VALUES (?1, ?2, ?3, ?4, ?5)
                        "#,
                        params![q.ts as i64, q.client_ip, q.domain, q.qtype, q.action],
                    )
                    .map_err(|e| format!("insert dns_query failed: {}", e))?;
                }
                StoreEvent::RecordAlert(a) => {
                    tx.execute(
                        r#"
                        INSERT INTO alerts (ts, severity, category, action, src_ip, dst_ip, dst_port, indicator, detail)
                        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                        "#,
                        params![
                            a.ts as i64,
                            a.severity,
                            a.category,
                            a.action,
                            a.src_ip,
                            a.dst_ip,
                            a.dst_port as i64,
                            a.indicator,
                            a.detail
                        ],
                    )
                    .map_err(|e| format!("insert alert failed: {}", e))?;
                }
                StoreEvent::RecordAudit(a) => {
                    tx.execute(
                        r#"
                        INSERT INTO audit_log (ts, actor, action, target, detail)
                        VALUES (?1, ?2, ?3, ?4, ?5)
                        "#,
                        params![a.ts as i64, a.actor, a.action, a.target, a.detail],
                    )
                    .map_err(|e| format!("insert audit failed: {}", e))?;
                }
                StoreEvent::Prune {
                    flow_dns_cutoff_ts,
                    audit_cutoff_ts,
                } => {
                    tx.execute(
                        "DELETE FROM flows WHERE ts < ?1",
                        params![*flow_dns_cutoff_ts as i64],
                    )
                    .map_err(|e| format!("prune flows failed: {}", e))?;
                    tx.execute(
                        "DELETE FROM dns_queries WHERE ts < ?1",
                        params![*flow_dns_cutoff_ts as i64],
                    )
                    .map_err(|e| format!("prune dns_queries failed: {}", e))?;
                    tx.execute(
                        "DELETE FROM alerts WHERE ts < ?1",
                        params![*audit_cutoff_ts as i64],
                    )
                    .map_err(|e| format!("prune alerts failed: {}", e))?;
                    tx.execute(
                        "DELETE FROM audit_log WHERE ts < ?1",
                        params![*audit_cutoff_ts as i64],
                    )
                    .map_err(|e| format!("prune audit_log failed: {}", e))?;
                }
                StoreEvent::Flush(_) => {}
            }
        }

        tx.commit()
            .map_err(|e| format!("failed to commit sqlite tx: {}", e))?;
        Ok(())
    }

    pub fn list_devices(&self, limit: usize) -> Result<Vec<DeviceRecord>, String> {
        let conn = self.conn.lock().map_err(|_| "store mutex poisoned".to_string())?;
        let mut stmt = conn
            .prepare(
                "SELECT mac, ip, hostname, first_seen, last_seen, bytes_tx, bytes_rx
                 FROM devices ORDER BY last_seen DESC LIMIT ?1",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(params![limit as i64], |r| {
                Ok(DeviceRecord {
                    mac: r.get(0)?,
                    ip: r.get(1)?,
                    hostname: r.get(2)?,
                    first_seen: r.get::<_, i64>(3)? as u64,
                    last_seen: r.get::<_, i64>(4)? as u64,
                    bytes_tx: r.get::<_, i64>(5)? as u64,
                    bytes_rx: r.get::<_, i64>(6)? as u64,
                })
            })
            .map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(|e| e.to_string())?);
        }
        Ok(out)
    }

    pub fn list_flows(&self, limit: usize) -> Result<Vec<FlowRecord>, String> {
        let conn = self.conn.lock().map_err(|_| "store mutex poisoned".to_string())?;
        let mut stmt = conn
            .prepare(
                "SELECT id, ts, proto, src_ip, src_port, dst_ip, dst_port, bytes_orig, bytes_reply, state
                 FROM flows ORDER BY id DESC LIMIT ?1",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(params![limit as i64], |r| {
                Ok(FlowRecord {
                    id: r.get(0)?,
                    ts: r.get::<_, i64>(1)? as u64,
                    proto: r.get(2)?,
                    src_ip: r.get(3)?,
                    src_port: r.get::<_, i64>(4)? as u16,
                    dst_ip: r.get(5)?,
                    dst_port: r.get::<_, i64>(6)? as u16,
                    bytes_orig: r.get::<_, i64>(7)? as u64,
                    bytes_reply: r.get::<_, i64>(8)? as u64,
                    state: r.get(9)?,
                })
            })
            .map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(|e| e.to_string())?);
        }
        Ok(out)
    }

    pub fn list_dns_queries(&self, limit: usize) -> Result<Vec<DnsQueryRecord>, String> {
        let conn = self.conn.lock().map_err(|_| "store mutex poisoned".to_string())?;
        let mut stmt = conn
            .prepare(
                "SELECT id, ts, client_ip, domain, qtype, action
                 FROM dns_queries ORDER BY id DESC LIMIT ?1",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(params![limit as i64], |r| {
                Ok(DnsQueryRecord {
                    id: r.get(0)?,
                    ts: r.get::<_, i64>(1)? as u64,
                    client_ip: r.get(2)?,
                    domain: r.get(3)?,
                    qtype: r.get(4)?,
                    action: r.get(5)?,
                })
            })
            .map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(|e| e.to_string())?);
        }
        Ok(out)
    }

    pub fn list_alerts(&self, limit: usize) -> Result<Vec<AlertRecord>, String> {
        let conn = self.conn.lock().map_err(|_| "store mutex poisoned".to_string())?;
        let mut stmt = conn
            .prepare(
                "SELECT id, ts, severity, category, action, src_ip, dst_ip, dst_port, indicator, detail
                 FROM alerts ORDER BY id DESC LIMIT ?1",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(params![limit as i64], |r| {
                Ok(AlertRecord {
                    id: r.get(0)?,
                    ts: r.get::<_, i64>(1)? as u64,
                    severity: r.get(2)?,
                    category: r.get(3)?,
                    action: r.get(4)?,
                    src_ip: r.get(5)?,
                    dst_ip: r.get(6)?,
                    dst_port: r.get::<_, i64>(7)? as u16,
                    indicator: r.get(8)?,
                    detail: r.get(9)?,
                })
            })
            .map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(|e| e.to_string())?);
        }
        Ok(out)
    }

    pub fn list_audit_log(&self, limit: usize) -> Result<Vec<AuditRecord>, String> {
        let conn = self.conn.lock().map_err(|_| "store mutex poisoned".to_string())?;
        let mut stmt = conn
            .prepare(
                "SELECT id, ts, actor, action, target, detail
                 FROM audit_log ORDER BY id DESC LIMIT ?1",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(params![limit as i64], |r| {
                Ok(AuditRecord {
                    id: r.get(0)?,
                    ts: r.get::<_, i64>(1)? as u64,
                    actor: r.get(2)?,
                    action: r.get(3)?,
                    target: r.get(4)?,
                    detail: r.get(5)?,
                })
            })
            .map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(|e| e.to_string())?);
        }
        Ok(out)
    }

    pub fn stats(&self) -> Result<DbStats, String> {
        let conn = self.conn.lock().map_err(|_| "store mutex poisoned".to_string())?;
        let devices_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM devices", [], |r| r.get(0))
            .map_err(|e| e.to_string())?;
        let flows_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM flows", [], |r| r.get(0))
            .map_err(|e| e.to_string())?;
        let dns_queries_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM dns_queries", [], |r| r.get(0))
            .map_err(|e| e.to_string())?;
        let alerts_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM alerts", [], |r| r.get(0))
            .map_err(|e| e.to_string())?;
        let audit_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM audit_log", [], |r| r.get(0))
            .map_err(|e| e.to_string())?;
        let db_size_bytes = fs::metadata(&self.path).map(|m| m.len()).unwrap_or(0);

        Ok(DbStats {
            devices_count: devices_count as u64,
            flows_count: flows_count as u64,
            dns_queries_count: dns_queries_count as u64,
            alerts_count: alerts_count as u64,
            audit_count: audit_count as u64,
            db_size_bytes,
        })
    }

    pub fn journal_mode(&self) -> Result<String, String> {
        let conn = self.conn.lock().map_err(|_| "store mutex poisoned".to_string())?;
        conn.query_row("PRAGMA journal_mode", [], |r| r.get(0))
            .map_err(|e| e.to_string())
    }
}

/// Non-blocking async handle that batches SQLite writes into periodic transactions.
#[derive(Clone)]
pub struct StoreWriter {
    tx: mpsc::Sender<StoreEvent>,
}

impl StoreWriter {
    pub fn spawn(store: Arc<Store>, flush_interval: Duration, retention_days: u64) -> Self {
        let (tx, mut rx) = mpsc::channel::<StoreEvent>(2048);

        tokio::spawn(async move {
            let mut batch: Vec<StoreEvent> = Vec::with_capacity(128);
            let mut flush_tick = tokio::time::interval(flush_interval);
            let mut prune_tick = tokio::time::interval(Duration::from_secs(3600));
            // Skip immediate first tick
            flush_tick.tick().await;
            prune_tick.tick().await;

            loop {
                tokio::select! {
                    maybe_ev = rx.recv() => {
                        match maybe_ev {
                            Some(StoreEvent::Flush(ack)) => {
                                if !batch.is_empty() {
                                    let to_write = std::mem::take(&mut batch);
                                    let st = Arc::clone(&store);
                                    let _ = tokio::task::spawn_blocking(move || st.apply_batch(&to_write)).await;
                                }
                                let _ = ack.send(());
                            }
                            Some(ev) => {
                                batch.push(ev);
                                if batch.len() >= 128 {
                                    let to_write = std::mem::take(&mut batch);
                                    let st = Arc::clone(&store);
                                    let _ = tokio::task::spawn_blocking(move || st.apply_batch(&to_write)).await;
                                }
                            }
                            None => {
                                if !batch.is_empty() {
                                    let to_write = std::mem::take(&mut batch);
                                    let st = Arc::clone(&store);
                                    let _ = tokio::task::spawn_blocking(move || st.apply_batch(&to_write)).await;
                                }
                                break;
                            }
                        }
                    }
                    _ = flush_tick.tick() => {
                        if !batch.is_empty() {
                            let to_write = std::mem::take(&mut batch);
                            let st = Arc::clone(&store);
                            let _ = tokio::task::spawn_blocking(move || st.apply_batch(&to_write)).await;
                        }
                    }
                    _ = prune_tick.tick() => {
                        let now = now_unix();
                        let flow_dns_cutoff = now.saturating_sub(retention_days * 86_400);
                        let audit_cutoff = now.saturating_sub(30 * 86_400);
                        let st = Arc::clone(&store);
                        let _ = tokio::task::spawn_blocking(move || {
                            st.apply_batch(&[StoreEvent::Prune {
                                flow_dns_cutoff_ts: flow_dns_cutoff,
                                audit_cutoff_ts: audit_cutoff,
                            }])
                        }).await;
                    }
                }
            }
        });

        Self { tx }
    }

    pub fn try_send(&self, event: StoreEvent) {
        let _ = self.tx.try_send(event);
    }

    pub async fn send(&self, event: StoreEvent) {
        let _ = self.tx.send(event).await;
    }

    pub async fn flush(&self) {
        let (ack_tx, ack_rx) = oneshot::channel();
        if self.tx.send(StoreEvent::Flush(ack_tx)).await.is_ok() {
            let _ = ack_rx.await;
        }
    }
}

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn batched_writer_persists_and_prunes_in_wal_mode() {
        let dir = std::env::temp_dir().join(format!("nulkast-fw-store-test-{}", now_unix()));
        let db_path = dir.join("nulkast.db");
        let store = Arc::new(Store::open(&db_path).expect("open db"));
        assert_eq!(store.journal_mode().unwrap().to_lowercase(), "wal");

        let writer = StoreWriter::spawn(Arc::clone(&store), Duration::from_secs(60), 7);
        writer
            .send(StoreEvent::UpsertDevice {
                mac: "AA:BB:CC:DD:EE:FF".into(),
                ip: "10.100.0.20".into(),
                hostname: "lan-client".into(),
                ts: 1000,
            })
            .await;
        writer
            .send(StoreEvent::RecordFlow(NewFlow {
                ts: 100,
                proto: "tcp".into(),
                src_ip: "10.100.0.20".into(),
                src_port: 51234,
                dst_ip: "10.200.0.2".into(),
                dst_port: 8080,
                bytes_orig: 256,
                bytes_reply: 512,
                state: "ESTABLISHED".into(),
            }))
            .await;
        writer
            .send(StoreEvent::RecordDnsQuery(NewDnsQuery {
                ts: 2000,
                client_ip: "10.100.0.20".into(),
                domain: "good.test".into(),
                qtype: "A".into(),
                action: "allowed".into(),
            }))
            .await;
        writer
            .send(StoreEvent::RecordAudit(NewAudit {
                ts: 2000,
                actor: "api".into(),
                action: "block_ip".into(),
                target: "10.200.0.2".into(),
                detail: "test".into(),
            }))
            .await;
        writer.flush().await;

        assert_eq!(store.list_devices(10).unwrap().len(), 1);
        assert_eq!(store.list_flows(10).unwrap().len(), 1);
        assert_eq!(store.list_dns_queries(10).unwrap().len(), 1);
        assert_eq!(store.list_audit_log(10).unwrap().len(), 1);

        // Prune old flow (ts=100 < cutoff=500), keep newer dns query (ts=2000)
        writer
            .send(StoreEvent::Prune {
                flow_dns_cutoff_ts: 500,
                audit_cutoff_ts: 500,
            })
            .await;
        writer.flush().await;

        assert_eq!(store.list_flows(10).unwrap().len(), 0);
        assert_eq!(store.list_dns_queries(10).unwrap().len(), 1);

        let _ = fs::remove_dir_all(&dir);
    }
}
