---
name: nulkast-fw-lab-and-qa
description: >-
  Use this skill when running, extending, or debugging NulKast-FW tests in
  /home/user/code/nulkast/nulkast-fw — including zero-host-install Dockerized cargo test (make test),
  the 3-namespace veth real-packet lab (ns-wan <-> ns-fw <-> ns-lan, make lab-test), and Phase 4-5
  Dockerized QEMU/KVM stock Debian VM validation.
---

# NulKast-FW Docker Lab & QA Verification Skill

## Core Rules
1. **Zero Host Installs:** Always run `make test` (`rust:1-bookworm` container with persistent Cargo cache volumes) and `make lab-test` (`nulkast-fw-lab:latest` privileged netns container). Never install Rust, dnsmasq, or QEMU onto the host.
2. **3-Namespace `veth` Lab Topology:** Uses `ip netns` (`ns-wan ↔ ns-fw ↔ ns-lan`) wired with direct `veth` pairs inside one container so Docker host `bridge-nf-call-iptables` never drops routed lab frames.
3. **Mandatory Phase 1 CORE Smoke Checks (`lab/smoke_test.sh`):**
   - LAN → WAN NAT masquerade (`client_ip=10.200.0.10`)
   - Unsolicited WAN → FW port 53 drop
   - Dynamic `block-ip` / `unblock-ip`
   - DNS sinkhole (`good.test → 10.200.0.2`, `bad.test → 0.0.0.0`)
   - MAC `pause-device` / `unpause-device`
   - 3s unconfirmed dead-man auto-rollback
4. **Phase 4–5 QEMU/KVM Gate:** WSL2 lacks `CONFIG_NET_SCH_CAKE`, so `tc CAKE` SQM, `systemd`, and reboot persistence are validated in a Dockerized QEMU/KVM stock Debian VM (`--device /dev/kvm`).
