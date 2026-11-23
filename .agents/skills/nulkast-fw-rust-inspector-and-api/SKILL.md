---
name: nulkast-fw-rust-inspector-and-api
description: >-
  Use this skill when writing or reviewing Rust code in /home/user/code/nulkast/nulkast-fw —
  including strict serde/TOML validation, zero-bloat Cargo.toml discipline, FoxIO JA4 TLS ClientHello
  fingerprinting, DNS wire parsing, multi-vendor rule/feed importers (IP/CIDR, Hosts/Adblock,
  JA4/SSLBL, Suricata .rules subset), async tokio/axum REST /api/v1 + WebSockets, and batched SQLite WAL.
---

# NulKast-FW Rust Inspector, Feeds & Async API Skill

## Core Invariants
1. **Strict Config Safety:** Annotate all config structs with `#[serde(deny_unknown_fields)]` so misplaced TOML keys fail loudly. Sanitize all interface names, IPv4/CIDR, MACs, ports, and domains before rendering kernel/daemon configs.
2. **FoxIO JA4 Official Spec (`PartA_PartB_PartC`):**
   - **Part A (10 chars):** `<t|q|d><tls_ver><d|i><cipher_cnt:02d><ext_cnt:02d><alpn_first_last|00>` (GREASE excluded from counts).
   - **Part B (12 hex):** GREASE-stripped ciphers sorted ascending hex → SHA-256[:12].
   - **Part C (12 hex):** GREASE/SNI/ALPN-stripped extensions sorted ascending hex + `_` + signature algorithms in wire order → SHA-256[:12].
3. **Selective Multi-Vendor Rule Ingestion:** Support IP/CIDR threat feeds (loaded into `nftables` sets), Domain/Hosts/Adblock lists (DNS + TLS SNI), JA4/SSLBL malware hashes, and a clean Suricata `.rules` subset (~12 modern keywords; cleanly skip/count unsupported legacy keywords).
4. **API-First Async Architecture:** All Web UI and CLI mutations use REST `/api/v1/...` (`axum` + `tokio`) + `/api/v1/ws/events` WebSocket stream. Zero-build vanilla HTML/CSS/JS embedded in the binary.
5. **SSD-Friendly SQLite WAL:** Embedded `rusqlite` (`journal_mode=WAL`, `synchronous=NORMAL`), 1–2s batched `mpsc` flushes, automatic 7–14 day raw flow/DNS pruning. Never use DuckDB on-box.
