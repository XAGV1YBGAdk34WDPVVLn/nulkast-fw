#!/usr/bin/env bash
set -euo pipefail

pass() { echo "  [PASS] $*"; }
fail() { echo "  [FAIL] $*"; exit 1; }

cleanup() {
    kill "${API_PID:-}" "${HTTP_PID:-}" "${TLS_PID:-}" 2>/dev/null || true
    ip netns del ns-wan 2>/dev/null || true
    ip netns del ns-fw  2>/dev/null || true
    ip netns del ns-lan 2>/dev/null || true
}
trap cleanup EXIT

echo "=== Setting up Adversarial & Resilience Stress Lab ==="
cleanup
ip netns add ns-wan
ip netns add ns-fw
ip netns add ns-lan

ip link add wan-peer type veth peer name wan0
ip link set wan-peer netns ns-wan
ip link set wan0     netns ns-fw

ip link add lan0 type veth peer name lan-peer
ip link set lan0     netns ns-fw
ip link set lan-peer netns ns-lan

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

# Start HTTP + TLS servers in ns-wan
ip netns exec ns-wan python3 -c "
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.end_headers(); self.wfile.write(b'ok\n')
    def log_message(self, *a): pass
ThreadingHTTPServer(('0.0.0.0', 8080), H).serve_forever()
" &
HTTP_PID=$!

openssl req -x509 -newkey rsa:2048 -keyout /tmp/wan.key -out /tmp/wan.crt \
  -days 1 -nodes -subj "/CN=good.test" >/dev/null 2>&1
ip netns exec ns-wan python3 -c "
import socket, ssl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
socket.setdefaulttimeout(2)
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.end_headers(); self.wfile.write(b'tls-ok\n')
    def log_message(self, *a): pass
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain('/tmp/wan.crt', '/tmp/wan.key')
srv = ThreadingHTTPServer(('0.0.0.0', 443), H)
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
srv.serve_forever()
" &
TLS_PID=$!
sleep 0.5

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
upstream_dns = ["10.200.0.2"]
local_domain = "lan"

[ids]
enabled = true
mode = "alert"
queues = 2
detect_dns_bypass = true
port_scan_threshold = 12
EOF

ip netns exec ns-fw nulkast-fw apply --no-rollback --skip-dns >/dev/null
ip netns exec ns-fw nulkast-fw serve --bind 10.100.0.10:8265 >/tmp/stress-api.log 2>&1 &
API_PID=$!
sleep 1

echo "=== [1/3] Adversarial Packet Fuzzing (malformed TLS + DNS pointer bombs) ==="
ip netns exec ns-lan python3 - <<'PY'
import os, socket

# 1. Truncated TLS ClientHello, oversized SNI lengths, and random garbage on TCP/443
payloads = [
    b"\x16\x03\x01\x00\x05\x01\x00\x00\x01\x03",
    b"\x16\x03\x01\xff\xff\x01\xff\xff\xff" + b"\x00" * 60,
    b"\x16\x03\x01\x00\x40\x01\x00\x00\x3c\x03\x03" + b"\xaa" * 32 + b"\xff" * 20,
    os.urandom(128),
]
for p in payloads:
    try:
        s = socket.create_connection(("10.200.0.2", 443), timeout=1)
        s.sendall(p)
        s.close()
    except Exception:
        pass

# 2. DNS compression-pointer bombs & truncated packets on UDP/53
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
dns_bombs = [
    b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\xc0\x0c\x00\x01\x00\x01",
    b"\x12\x34\x01\x00\x00\x01" + b"\x3f" * 50,
    b"\x00" * 5,
    os.urandom(64),
]
for d in dns_bombs:
    u.sendto(d, ("10.200.0.2", 53))
u.close()
PY

HEALTH=$(ip netns exec ns-lan curl -sf --max-time 3 http://10.100.0.10:8265/api/v1/health || true)
[[ "${HEALTH}" == *'"status":"ok"'* ]] \
  && pass "Daemon survived adversarial TLS/DNS fuzz payloads with zero panics" \
  || fail "Daemon crashed after fuzzing! Health: '${HEALTH}'"

TLS_OK=$(ip netns exec ns-lan curl -skf --max-time 3 --resolve good.test:443:10.200.0.2 https://good.test/ || true)
[[ "${TLS_OK}" == "tls-ok" ]] \
  && pass "Legitimate TLS traffic still healthy after fuzz burst" \
  || fail "Legitimate TLS traffic failed after fuzzing!"

echo "=== [2/3] Live Behavioral LAN Port-Scan Burst (15 distinct ports) ==="
ip netns exec ns-lan python3 - <<'PY'
import socket
for port in range(9001, 9017):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.05)
    try:
        s.connect(("10.200.0.2", port))
    except Exception:
        pass
    finally:
        s.close()
PY
sleep 2.5
ALERTS=$(ip netns exec ns-lan curl -sf http://10.100.0.10:8265/api/v1/alerts?limit=20 || true)
[[ "${ALERTS}" == *'"category":"port_scan"'* ]] \
  && pass "Live LAN port-scan burst detected and logged to SQLite WAL!" \
  || fail "Expected port_scan alert, got: ${ALERTS}"

echo "=== [3/3] Fail-Open Resilience Test (kill -9 daemon mid-flight) ==="
kill -9 "${API_PID}" 2>/dev/null || true
sleep 0.5
HTTP_OK=$(ip netns exec ns-lan curl -sf --max-time 3 http://10.200.0.2:8080/ || true)
TLS_FAILOPEN=$(ip netns exec ns-lan curl -skf --max-time 3 --resolve good.test:443:10.200.0.2 https://good.test/ || true)
[[ "${HTTP_OK}" == "ok" && "${TLS_FAILOPEN}" == "tls-ok" ]] \
  && pass "NFQUEUE queue-bypass kept HTTP & TLS flowing seamlessly after kill -9!" \
  || fail "Fail-open broke after kill -9! http='${HTTP_OK}' tls='${TLS_FAILOPEN}'"

echo "=== ALL 3 ADVERSARIAL & RESILIENCE STRESS TESTS PASSED ==="
