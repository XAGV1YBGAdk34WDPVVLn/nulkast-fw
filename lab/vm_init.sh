#!/bin/sh
export PATH=/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev 2>/dev/null || true

echo "=== Booted Stock Debian Kernel: $(uname -r) ==="

# Load real stock Debian networking & CAKE SQM kernel modules
modprobe dummy
modprobe ifb
modprobe sch_cake
modprobe cls_u32
modprobe act_mirred

# Create a virtual WAN interface inside the real Debian kernel
ip link add wan0 type dummy
ip link set wan0 up
ip link add lan0 type dummy
ip link set lan0 up

mkdir -p /etc/nulkast-fw /var/lib/nulkast-fw
cat >/etc/nulkast-fw/config.toml <<'EOF'
blocked_ips = []
blocked_domains = []
paused_macs = []
allowed_ports = []
static_leases = []
local_hosts = []

[interfaces]
wan = "wan0"
lan = ["lan0"]

[dhcp]
enabled = false
range_start = "10.100.0.50"
range_end = "10.100.0.200"
lease_time = "12h"
upstream_dns = ["1.1.1.1"]
local_domain = "lan"

[sqm]
enabled = true
download_mbps = 950
upload_mbps = 35
overhead = "docsis"
ifb_dev = "ifb-dl"
EOF

echo "[1/3] Applying DOCSIS CAKE SQM via nulkast-fw sqm apply..."
if ! nulkast-fw sqm apply; then
    echo "[FAIL] nulkast-fw sqm apply failed!"
    poweroff -f
fi

EGRESS=$(/sbin/tc -s qdisc show dev wan0)
INGRESS=$(/sbin/tc -s qdisc show dev ifb-dl)
echo "--- Egress qdisc (wan0) ---"
echo "${EGRESS}"
echo "--- Ingress qdisc (ifb-dl) ---"
echo "${INGRESS}"

echo "[2/3] Verifying DOCSIS CAKE parameters on wan0 and ifb-dl..."
echo "${EGRESS}" | grep -q "qdisc cake" && \
echo "${EGRESS}" | grep -q "bandwidth 35Mbit" && \
echo "${EGRESS}" | grep -q "diffserv4" && \
echo "${EGRESS}" | grep -q "dual-srchost" && \
echo "${EGRESS}" | grep -q "nat" && \
echo "${EGRESS}" | grep -q "overhead 18" || {
    echo "[FAIL] Egress CAKE qdisc missing expected DOCSIS params!"
    poweroff -f
}
echo "  [PASS] wan0 egress CAKE verified (35Mbit, DOCSIS overhead 18, dual-srchost, nat, diffserv4)"

echo "${INGRESS}" | grep -q "qdisc cake" && \
echo "${INGRESS}" | grep -q "bandwidth 950Mbit" && \
echo "${INGRESS}" | grep -q "diffserv4" && \
echo "${INGRESS}" | grep -q "dual-dsthost" && \
echo "${INGRESS}" | grep -q "ingress" && \
echo "${INGRESS}" | grep -q "overhead 18" || {
    echo "[FAIL] Ingress IFB CAKE qdisc missing expected DOCSIS params!"
    poweroff -f
}
echo "  [PASS] ifb-dl ingress CAKE verified (950Mbit, DOCSIS overhead 18, dual-dsthost, ingress, diffserv4)"

echo "[3/3] Testing nulkast-fw sqm disable teardown..."
nulkast-fw sqm disable
if ip link show ifb-dl >/dev/null 2>&1; then
    echo "[FAIL] ifb-dl still exists after sqm disable!"
    poweroff -f
fi
echo "  [PASS] nulkast-fw sqm disable cleaned up qdiscs and ifb-dl"
echo "VM_SQM_ALL_PASSED"
poweroff -f
