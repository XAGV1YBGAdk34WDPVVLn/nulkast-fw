# NulKast-FW (`nulkast-fw`) — Core-First Modular Build Plan

> **Goal:** Build our own lean, modular home firewall / IDS / IPS / traffic shaper on **stock minimal Debian Linux** — 100% our own **Rust** codebase driving proven Linux kernel primitives (`nftables`, `conntrack`, `NFQUEUE`, `tc CAKE`) + `dnsmasq`.  
> **Target Hardware:** **GEEKOM iX12** (Intel N95 4c/4t, 8 GB DDR5, 256 GB M.2 SATA SSD, **4× Intel I226-V 2.5GbE**, fanless aluminum chassis, USB-C UART serial console).  
> **Guiding Principle:** Start small, keep every module tight and independent, prove **CORE** works rock-solid in a local virtual lab, and only add the next layer once the previous one is battle-tested.

---

## 1. Anti-Bloat & Modularity Guardrails

- **Stock Debian Kernel Only:** No custom Linux kernel. Everything we need (`nftables`, `conntrack`, `NFQUEUE`, `eBPF/XDP`, `sch_cake`, Intel `igc` driver for I226-V) is already built into stock Debian 6.x with automatic CVE patches.
- **Lean Rust Binary (`nulkast-fw`):**
  - Memory-safe parsing of untrusted WAN/LAN packets (no buffer overflows or C footguns).
  - Zero GC pauses in the inline `NFQUEUE` packet path.
  - Ultra-low RAM (~5–15 MB) & CPU footprint — keeps the **fanless N95** cool and silent 24/7.
  - **Crate discipline:** Keep `Cargo.toml` intentionally small (minimal dependencies = fast incremental compiles, small attack surface).
- **No Suricata Bloat:** We build our own lean packet/metadata inspector (`inspect`) in Rust focusing on what actually matters on encrypted modern networks (DNS, TLS SNI, JA4, threat feeds, behavioral rules) and selectively ingesting vendor/open rule formats.
- **No Heavy Observability Stack:** Single-file **SQLite (WAL mode)** with automatic retention pruning. No Grafana/Prometheus/ELK.
- **Fail-Safe Separation:** Baseline WAN/LAN NAT + routing stays in a small static `nftables` skeleton. Our daemon only mutates dynamic `nftables` sets and `NFQUEUE` with `queue-bypass` (fail-open), so a crash or restart never kills the house internet.
- **No MITM HTTPS Decryption:** Metadata/SNI/JA4/DNS inspection only — never break TLS or install custom root CAs on family devices.

---

## 2. Target Hardware Mapping — GEEKOM iX12

| Hardware Spec | How NulKast-FW Uses It |
| :--- | :--- |
| **Intel N95 (4c/4t, AES-NI, 15W TDP)** | Multi-queue `NFQUEUE` across 4 cores + TLS fast-path offload → 1 Gbps line-rate without heating up the fanless chassis |
| **4× Intel I226-V 2.5GbE** (`igc` driver) | `eth0` (`wan0`) → Spectrum DOCSIS 3.1 Modem (full ~1.15 Gbps) · `eth1` (`lan0`) → Wired LAN / Switch · `eth2` (`lan1`) → Nest WiFi · `eth3` (`mgmt0`) → Dedicated rescue/admin port |
| **8 GB DDR5-4800** | Huge headroom — our Rust daemon + `dnsmasq` + SQLite uses < 150 MB total (leaving > 7 GB free for kernel buffers & page cache) |
| **256 GB M.2 SATA SSD** | Write-friendly SQLite WAL + batched flushes + retention pruning to maximize SSD longevity |
| **USB-C UART Serial Console** | Enabled in Debian `install.sh` (`serial-getty`) as a physical hardware backdoor if SSH/firewall rules are ever misconfigured |

---

## 3. Modular Architecture

```text
                nulkast-fw (Single Modular Rust Binary)
  ┌──────────────┬───────────────┬──────────────┬──────────────┐
  │ Phase 1 CORE │  Phase 2 UI   │ Phase 3 IDS  │ Phase 4 SQM  │
  │  src/nft/    │  src/store/   │ src/inspect/ │ src/shaper/  │
  │  src/dns/    │  src/api/     │ src/feeds/   │              │
  │  + rollback  │  + web/ (HTML)│              │              │
  └──────┬───────┴───────┬───────┴──────┬───────┴──────┬───────┘
         ▼               ▼              ▼              ▼
    [ nftables ]    [ SQLite WAL ]  [ NFQUEUE ]    [ tc CAKE ]
    [ dnsmasq  ]    [ conntrack  ]  (fail-open)    (DOCSIS SQM)
                 Stock Minimal Debian 6.x Kernel
```

---

## 4. Core-First Phased Roadmap

> **Rule:** Do **not** start Phase *N+1* until Phase *N* passes all automated tests inside our local virtual lab.

### Phase 0 — Local Virtual Network Lab (Docker)
*A repeatable 3-namespace Linux lab (`ns-wan` ↔ `ns-fw` ↔ `ns-lan`) booting in < 1 second inside a single Docker container to test real packets safely before hardware arrives.*
- [x] Isolated 3-namespace `veth` topology inside Docker (`lab/Dockerfile.lab`, `CAP_NET_ADMIN`)
- [x] Rust builder container (zero host toolchain clutter)
- [x] `lab/smoke_test.sh` harness verifying NAT, default-drop inbound, DNS, blocking, and rollback automatically

### Phase 1 — CORE (Must Be Rock-Solid First)
*A tight, dependable router & firewall engine with zero UI bloat yet.*
- [x] **`src/config.rs`**: Strict TOML state file (`#[serde(deny_unknown_fields)]`) + snapshot history
- [x] **`src/nft.rs`**:
  - Static baseline template (WAN→LAN default drop, LAN→WAN masquerade, established/related, ICMP/DHCP, dedicated `mgmt0` rescue allow)
  - Dynamic kernel sets: `blocked_ips`, `paused_macs`, `allowed_ports`
  - **Atomic validation (`nft -c -f`) + 60-second dead-man rollback**
- [x] **`src/dns.rs`**:
  - Minimal `dnsmasq` config generator (DHCP leases, static reservations, local DNS, query logging, domain sinkhole file)
  - Lease parser (maps IP ↔ MAC ↔ Hostname)
- [x] **CLI (`nulkast-fw`)**:
  - `status`, `apply`, `confirm`, `rollback`, `devices`, `block-ip`, `unblock-ip`, `block-domain`, `pause-device`
- [x] **Core Exit Gate:** Lab test proves LAN→WAN NAT works, unsolicited WAN→LAN is dropped, `block-ip` / `block-domain` / `pause-device` enforce immediately, and an unconfirmed rule auto-reverts in 60s.

### Phase 2 — Live Visibility & Minimal Web UI
*See what devices are doing in real time and make 1-click decisions.*
- [x] **`src/store.rs`**: SQLite WAL schema (devices, active/recent flows, DNS queries, audit log) + auto-pruning + 1.5s batched `mpsc` writes (SSD-friendly)
- [x] **`src/collector.rs`**: Async background collector (`conntrack -L`, `dnsmasq.log` tailer, `ip neigh` + DHCP leases)
- [x] **`src/api.rs` + `web/`**:
  - Lightweight `axum` async REST `/api/v1/...` + `/api/v1/ws/events` WebSocket server with embedded zero-build HTML/CSS/JS UI (allocated port `8265`, LAN/mgmt only)
  - Live feed: `Device → Domain / IP → Bytes → Status`
  - 1-click actions: Block IP, Block Domain, Pause Device, Open/Close Port, Confirm/Rollback
  - **Internal Home DNS Manager (`/api/v1/dns/hosts`)**: Full CRUD for custom local DNS records (e.g., `nas.lan`, `fw.lan`, `printer.lan`) + automatic DHCP hostname resolution (`*.lan` / `local_domain`) served by `dnsmasq`

### Phase 3 — Our Own Lean IDS/IPS & Multi-Vendor Rule Ingestion
*Custom Rust inspector (`src/inspect/`) + rule/feed importers (`src/feeds/`).*
- [ ] **`src/inspect/`** (Linux `NFQUEUE` across 4 queues `0:3` for N95's 4 cores, with `queue-bypass` fail-open):
  - Memory-safe Rust parsers for **TLS ClientHello** (SNI + JA4 fingerprint) and **DNS** packets; fast-path the rest of each encrypted stream via `conntrack` mark so 4K movies & 1 Gbps downloads run at wire speed
  - Behavioral detectors: LAN port-scan detection, DNS-bypass detection (hardcoded `8.8.8.8`), new-destination alerts
  - Starts in **`ALERT` (IDS)** mode; 1-click UI toggle to promote specific rules/feeds to **`DROP` (IPS)**
- [ ] **`src/feeds/`** (Modular rule & threat-feed importers):
  - **IP / CIDR lists** (Spamhaus DROP, FireHOL, Abuse.ch Feodo) → loaded straight into kernel `nftables` sets
  - **Domain lists** (Hosts, Adblock `||domain^`, Hagezi/OISD, NulKast lists) → enforced at both DNS & TLS SNI
  - **JA4 / JA3 TLS malware lists** (Abuse.ch SSLBL)
  - **Suricata `.rules` subset importer** (~12 high-value modern keywords: IP/port, `dns.query`, `tls.sni`, `tls.cert_subject`, `ja4.hash`, `http.host`, `http.uri`, `content`, `nocase`, `sid`, `msg`, `classtype`; cleanly skips unsupported legacy keywords)

### Phase 4 — Traffic Shaping (`src/shaper/`) — Tested in QEMU/KVM Debian VM
*Kill Spectrum cable upload bufferbloat automatically (verified in real stock Debian kernel via QEMU/KVM since WSL2 lacks `sch_cake`).*
- [ ] `tc` + `sch_cake` wrapper (WAN egress + IFB ingress, `diffserv4`, `nat`, `dual-srchost`/`dual-dsthost`, `docsis` overhead)
- [ ] 1-panel UI: set Spectrum Down/Up Mbps + optional per-device rate ceiling

### Phase 5 — GEEKOM iX12 Hardware Cutover & Hardening
*Deploy cleanly to the GEEKOM iX12 running stock minimal Debian.*
- [ ] Idempotent `scripts/install.sh` (systemd unit, `sysctl.conf` tuning, `unattended-upgrades`, SSH key-only on LAN/mgmt, USB-C UART serial console enabled, I226-V interface pinning by MAC)
- [ ] Spectrum 2-box cutover runbook (remove Spectrum router, 30s modem power-cycle, plug `wan0` into modem, `lan0` into wired LAN, `lan1` into Nest WiFi, `mgmt0` reserved for rescue)

---

## 5. Explicitly Deferred (Not in v1)
- WireGuard VPN
- VLANs / IoT isolation (revisit only if/when replacing Nest WiFi with VLAN-capable APs)
- GeoIP country blocking
- CrowdSec agent integration

---

## 6. Repo Layout (`nulkast-fw/`)

```text
nulkast-fw/
├── PLAN.md                 # This plan
├── README.md               # Quick overview & build commands
├── Cargo.toml              # Lean Rust manifest (minimal crates)
├── src/
│   ├── main.rs             # CLI + daemon entrypoint
│   ├── config/             # State file + snapshot management
│   ├── nft/                # Phase 1: nftables generator, validator, 60s rollback
│   ├── dns/                # Phase 1: dnsmasq generator + lease/query reader
│   ├── store/              # Phase 2: SQLite WAL store + batched writes + pruning
│   ├── api/                # Phase 2: axum REST API + WebSocket hub
│   ├── inspect/            # Phase 3: NFQUEUE TLS/SNI/JA4/DNS + behavioral IDS/IPS
│   ├── feeds/              # Phase 3: IP, Domain, JA4, Suricata-subset importers
│   └── shaper/             # Phase 4: tc CAKE SQM wrapper
├── web/                    # Phase 2: Zero-build HTML/JS UI (embedded in binary)
├── lab/                    # Phase 0: Local 3-container Docker lab (+ Phase 4 QEMU VM)
└── scripts/                # Phase 5: GEEKOM iX12 Debian install.sh, sysctl, backup
```
