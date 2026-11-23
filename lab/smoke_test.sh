#!/usr/bin/env bash
set -euo pipefail

pass() { echo "  [PASS] $*"; }
fail() { echo "  [FAIL] $*"; exit 1; }

cleanup() {
    ip netns del ns-wan 2>/dev/null || true
    ip netns del ns-fw  2>/dev/null || true
    ip netns del ns-lan 2>/dev/null || true
}
trap cleanup EXIT

echo "=== Setting up 3-Namespace Virtual Network Lab (ns-wan <-> ns-fw <-> ns-lan) ==="
cleanup
ip netns add ns-wan
ip netns add ns-fw
ip netns add ns-lan

# Wire ns-wan (wan-peer) <---> ns-fw (wan0)
ip link add wan-peer type veth peer name wan0
ip link set wan-peer netns ns-wan
ip link set wan0     netns ns-fw

# Wire ns-fw (lan0) <---> ns-lan (lan-peer)
ip link add lan0 type veth peer name lan-peer
ip link set lan0     netns ns-fw
ip link set lan-peer netns ns-lan

# Bring up loopbacks & interfaces
ip netns exec ns-wan ip link set lo up
ip netns exec ns-wan ip link set wan-peer up
ip netns exec ns-wan ip addr add 10.200.0.2/24 dev wan-peer

ip netns exec ns-fw ip link set lo up
ip netns exec ns-fw ip link set wan0 up
ip netns exec ns-fw ip link set lan0 up
ip netns exec ns-fw ip addr add 10.200.0.10/24 dev wan0
ip netns exec ns-fw ip addr add 10.100.0.10/24 dev lan0
ip netns exec ns-fw sysctl -qw net.ipv4.ip_forward=1

ip netns exec ns-lan ip link set lo up
ip netns exec ns-lan ip link set lan-peer up
ip netns exec ns-lan ip addr add 10.100.0.20/24 dev lan-peer
ip netns exec ns-lan ip route add default via 10.100.0.10

# Start HTTP echo server in ns-wan (returns observed client IP to prove NAT)
ip netns exec ns-wan python3 -c "
from http.server import BaseHTTPRequestHandler, HTTPServer
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        b = f'client_ip={self.client_address[0]}\n'.encode()
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.send_header('Content-Length', str(len(b)))
        self.end_headers()
        self.wfile.write(b)
    def log_message(self, *a): pass
HTTPServer(('0.0.0.0', 8080), H).serve_forever()
" &
sleep 0.5

# Write initial NulKast-FW config inside container
mkdir -p /etc/nulkast-fw /var/lib/nulkast-fw
cat >/etc/nulkast-fw/config.toml <<'EOF'
blocked_ips = []
blocked_domains = []
paused_macs = []
allowed_ports = []
static_leases = []
local_hosts = [
  ["good.test", "10.200.0.2"],
  ["bad.test", "10.200.0.2"],
]

[interfaces]
wan = "wan0"
lan = ["lan0"]

[dhcp]
enabled = false
range_start = "10.100.0.50"
range_end = "10.100.0.200"
lease_time = "12h"
upstream_dns = ["10.200.0.2"]
local_domain = "lan"
EOF

ip netns exec ns-fw nulkast-fw apply --no-rollback
ip netns exec ns-fw nulkast-fw status

echo "=== NulKast-FW Phase 1 CORE Real-Packet Smoke Test ==="

# 1. LAN -> WAN NAT masquerade
echo "[1/6] Testing LAN -> WAN NAT masquerade..."
RESP=$(ip netns exec ns-lan curl -sf --max-time 3 http://10.200.0.2:8080/ || true)
[[ "${RESP}" == "client_ip=10.200.0.10" ]] \
  && pass "lan-client reached wan-sim via NAT (${RESP})" \
  || fail "expected client_ip=10.200.0.10, got '${RESP}'"

# 2. WAN -> FW unsolicited drop
echo "[2/6] Testing WAN -> FW unsolicited input drop..."
if ip netns exec ns-wan nc -z -w 2 10.200.0.10 53 2>/dev/null; then
  fail "WAN was able to reach DNS port 53 on firewall!"
else
  pass "unsolicited WAN probe to firewall port 53 dropped"
fi

# 3. Dynamic block-ip / unblock-ip
echo "[3/6] Testing block-ip / unblock-ip..."
ip netns exec ns-fw nulkast-fw block-ip 10.200.0.2 >/dev/null
if ip netns exec ns-lan curl -sf --max-time 2 http://10.200.0.2:8080/ >/dev/null 2>&1; then
  fail "lan-client still reached blocked IP 10.200.0.2!"
else
  pass "blocked IP 10.200.0.2 dropped immediately"
fi
ip netns exec ns-fw nulkast-fw unblock-ip 10.200.0.2 >/dev/null
RESP=$(ip netns exec ns-lan curl -sf --max-time 3 http://10.200.0.2:8080/ || true)
[[ "${RESP}" == "client_ip=10.200.0.10" ]] \
  && pass "unblock-ip restored connectivity" \
  || fail "unblock-ip did not restore connectivity"

# 4. DNS sinkhole
echo "[4/6] Testing DNS sinkhole (good.test vs bad.test)..."
GOOD_IP=$(ip netns exec ns-lan dig +short @10.100.0.10 good.test | tail -n1)
[[ "${GOOD_IP}" == "10.200.0.2" ]] \
  && pass "good.test resolved to ${GOOD_IP}" \
  || fail "expected good.test -> 10.200.0.2, got '${GOOD_IP}'"

ip netns exec ns-fw nulkast-fw block-domain bad.test >/dev/null
BAD_IP=$(ip netns exec ns-lan dig +short @10.100.0.10 bad.test | tail -n1)
[[ "${BAD_IP}" == "0.0.0.0" ]] \
  && pass "bad.test sinkholed to 0.0.0.0" \
  || fail "expected bad.test -> 0.0.0.0, got '${BAD_IP}'"
ip netns exec ns-fw nulkast-fw unblock-domain bad.test >/dev/null

# 5. Pause / unpause device by MAC
echo "[5/6] Testing pause-device / unpause-device by MAC..."
LAN_MAC=$(ip netns exec ns-lan ip -o link show lan-peer | awk '{for(i=1;i<=NF;i++) if($i=="link/ether") print $(i+1)}')
ip netns exec ns-fw nulkast-fw pause-device "${LAN_MAC}" >/dev/null
if ip netns exec ns-lan curl -sf --max-time 2 http://10.200.0.2:8080/ >/dev/null 2>&1; then
  fail "paused MAC ${LAN_MAC} still reached WAN!"
else
  pass "paused MAC ${LAN_MAC} blocked from WAN"
fi
ip netns exec ns-fw nulkast-fw unpause-device "${LAN_MAC}" >/dev/null
RESP=$(ip netns exec ns-lan curl -sf --max-time 3 http://10.200.0.2:8080/ || true)
[[ "${RESP}" == "client_ip=10.200.0.10" ]] \
  && pass "unpause-device restored MAC ${LAN_MAC}" \
  || fail "unpause-device did not restore connectivity"

# 6. Dead-man auto-rollback (3s test window, intentionally NOT confirmed)
echo "[6/6] Testing dead-man auto-rollback (3s window, unconfirmed)..."
sed -i 's/blocked_ips = \[\]/blocked_ips = ["10.200.0.2"]/' /etc/nulkast-fw/config.toml
ip netns exec ns-fw nulkast-fw apply --rollback-secs 3 --skip-dns >/dev/null
if ip netns exec ns-lan curl -sf --max-time 2 http://10.200.0.2:8080/ >/dev/null 2>&1; then
  fail "candidate breaking rule did not take effect before rollback!"
else
  pass "candidate rule active during rollback window"
fi
sleep 4
RESP=$(ip netns exec ns-lan curl -sf --max-time 3 http://10.200.0.2:8080/ || true)
[[ "${RESP}" == "client_ip=10.200.0.10" ]] \
  && pass "unconfirmed rule auto-reverted after 3s — connectivity restored!" \
  || fail "dead-man rollback did not restore connectivity"

echo "=== ALL 6 PHASE 1 CORE LAB TESTS PASSED ==="
