---
name: nulkast-fw-kernel-and-netfilter
description: >-
  Use this skill when designing, modifying, or debugging NulKast-FW Linux networking in
  /home/user/code/nulkast/nulkast-fw — including atomic nftables generation (delete table + recreate),
  60s dead-man rollback, dnsmasq DHCP/DNS sinkholing, multi-queue NFQUEUE bypass + ct mark flowtable
  fast-path, tc sch_cake DOCSIS SQM with IFB ingress, and GEEKOM iX12 Debian 6.x hardware tuning.
---

# NulKast-FW Kernel, Netfilter & SQM Skill

## Core Invariants
1. **Atomic `nftables` Replacement:** Always emit `table <fam> <name>` + `delete table <fam> <name>` before recreating `inet nulkast_fw` and `ip nulkast_nat`. Never rely on `flush table`, which leaves named set elements (`blocked_ips`, `paused_macs`) stale.
2. **Pre-Validation & Rollback:** Always run `nft -c -f` before `nft -f`, and arm the detached rollback watchdog (`nulkast-fw apply --rollback-secs 60`) on live changes so unconfirmed lockouts self-revert.
3. **`dnsmasq` Ordering:** Always validate with `dnsmasq --test -C <conf>` and include `sinkhole.conf` *after* `local_hosts` so blocked domains (`0.0.0.0`) always take precedence.
4. **NFQUEUE + Flowtable Fast-Path (Phase 3):** Use `queue num 0-3 bypass` (4 cores on Intel N95, fail-open). Assign `ct mark` on initial handshake (`ct state new` / unmarked) and only offload to `flowtable` after inspection completes.
5. **DOCSIS SQM (`tc sch_cake`, Phase 4):**
   - Egress: `tc qdisc replace dev $WAN root cake bandwidth ${UL}mbit docsis dual-srchost nat diffserv4`
   - Ingress (via `ifb-dl`): `tc qdisc replace dev ifb-dl root cake bandwidth ${DL}mbit docsis dual-dsthost ingress diffserv4`
6. **GEEKOM iX12 Hardware Target:** Stock minimal Debian 6.x (never custom kernel), 4× Intel I226-V (`igc`: `wan0`, `lan0`, `lan1` Nest WiFi, `mgmt0` rescue), USB-C UART serial console enabled.
