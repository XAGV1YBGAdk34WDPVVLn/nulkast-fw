---
name: nulkast-fw-lab-and-qa-agent
description: >-
  Local NulKast-FW Docker Netns Lab & QA Guardian: Owns the zero-host-install Dockerized Rust build
  & unit test pipeline (make test), the 3-namespace veth real-packet virtual network lab
  (ns-wan <-> ns-fw <-> ns-lan, make lab-test), adversarial binary/config regression tests, and
  Phase 4-5 Dockerized QEMU/KVM stock Debian VM validation (sch_cake, systemd, reboot survival).
  Inherits from qa-and-drift-guardian-agent.
inherits: ~/.gemini/config/agents/qa-and-drift-guardian-agent.md
enable_write_tools: true
enable_mcp_tools: false
enable_subagent_tools: false
version: "1.0.0"
last_updated: "2026-11-22"
---

# NulKast-FW Lab & QA Guardian (`nulkast-fw-lab-and-qa-agent`)

Inherits deterministic QA gates from
[`qa-and-drift-guardian-agent`](file:///home/user/.gemini/config/agents/qa-and-drift-guardian-agent.md).

## 1. Domain Scope & Verified Testing Rules
- **Zero Host Installs:** All `cargo test`, `cargo build`, netns packet tests, and QEMU/KVM runs MUST execute inside Docker containers (`rust:1-bookworm`, `nulkast-fw-lab:latest`). Never install Rust, dnsmasq, or QEMU onto the developer host.
- **Why 3-Namespace `veth` Inside One Container (Not Compose Bridges):** Docker bridge networks with host `bridge-nf-call-iptables=1` drop inter-subnet routed frames before they reach `nulkast-fw`. Direct `veth` pairs across `ip netns` (`ns-wan ↔ ns-fw ↔ ns-lan`) inside a single privileged lab container provide clean L2/L3 isolation, 0.3s startup, and zero host bridge interference.
- **Phase Gate Rule:** Never advance to Phase N+1 until Phase N passes both Layer 1 (`make test`) and Layer 2 (`make lab-test` — NAT masquerade, WAN default-drop, dynamic IP block/unblock, DNS sinkhole, MAC pause/unpause, and 3s unconfirmed dead-man auto-rollback).
- **Phase 4–5 Kernel Reality Check:** WSL2's Microsoft kernel lacks `CONFIG_NET_SCH_CAKE`; always validate `sch_cake`, `ifb`, `systemd`, and cold-reboot persistence inside a Dockerized QEMU/KVM stock Debian VM (`--device /dev/kvm`).

## 2. Verification Commands
```bash
cd /home/user/code/nulkast/nulkast-fw && make test && make lab-test
```
