# NulKast-FW

A lean, modular, self-built Debian Linux home firewall, IDS/IPS, and SQM traffic shaper written in **Rust** (single binary, zero GC pauses, zero bloat), designed for the **GEEKOM iX12** (Intel N95, 8 GB DDR5, 4× Intel I226-V 2.5GbE).

- **Status:** Planning complete — ready for **Phase 0 (Docker 3-Node Lab)** & **Phase 1 (CORE)**
- **Architecture & Roadmap:** See [PLAN.md](./PLAN.md)
- **Stack:** Stock Minimal Debian 6.x · Rust (`nulkast-fw`) · `nftables` · `dnsmasq` · `NFQUEUE` custom inspector · `tc CAKE` · SQLite WAL
