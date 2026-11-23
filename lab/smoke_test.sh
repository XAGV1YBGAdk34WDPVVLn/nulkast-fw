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

[ids]
enabled = true
mode = "alert"
queues = 2
detect_dns_bypass = true
port_scan_threshold = 12
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

echo "=== NulKast-FW Phase 2 Async REST API & Live Visibility Tests ==="

# Start Phase 2 async API + SQLite WAL collector inside ns-fw
ip netns exec ns-fw nulkast-fw serve --bind 10.100.0.10:8265 >/tmp/nulkast-api.log 2>&1 &
API_PID=$!
trap 'kill "${API_PID}" 2>/dev/null || true; cleanup' EXIT
sleep 1

# 7. REST API health + embedded UI + WAN isolation check
echo "[7/10] Testing REST /api/v1/health, embedded UI, and WAN isolation..."
HEALTH=$(ip netns exec ns-lan curl -sf --max-time 3 http://10.100.0.10:8265/api/v1/health || true)
[[ "${HEALTH}" == *'"status":"ok"'* ]] \
  && pass "LAN reached REST /api/v1/health (${HEALTH})" \
  || fail "REST health check failed: '${HEALTH}'"

UI_HTML=$(ip netns exec ns-lan curl -sf --max-time 3 http://10.100.0.10:8265/ || true)
[[ "${UI_HTML}" == *'NulKast-FW'* ]] \
  && pass "Embedded zero-build Web UI served at /" \
  || fail "Embedded Web UI failed"

if ip netns exec ns-wan nc -z -w 2 10.200.0.10 8265 2>/dev/null; then
  fail "WAN was able to reach management API port 8265!"
else
  pass "WAN probe to API port 8265 blocked by default-drop"
fi

# 8. REST API IP block & unblock enforces real packet drop
echo "[8/10] Testing REST POST/DELETE /api/v1/rules/ips enforcement..."
ip netns exec ns-lan curl -sf -X POST http://10.100.0.10:8265/api/v1/rules/ips \
  -H 'Content-Type: application/json' -d '{"ip":"10.200.0.2"}' >/dev/null
if ip netns exec ns-lan curl -sf --max-time 2 http://10.200.0.2:8080/ >/dev/null 2>&1; then
  fail "REST block-ip did not drop traffic to 10.200.0.2!"
else
  pass "REST POST /api/v1/rules/ips dropped live WAN traffic"
fi
ip netns exec ns-lan curl -sf -X DELETE http://10.100.0.10:8265/api/v1/rules/ips/10.200.0.2 >/dev/null
RESP=$(ip netns exec ns-lan curl -sf --max-time 3 http://10.200.0.2:8080/ || true)
[[ "${RESP}" == "client_ip=10.200.0.10" ]] \
  && pass "REST DELETE /api/v1/rules/ips restored live WAN traffic" \
  || fail "REST DELETE /api/v1/rules/ips did not restore traffic"

# 9. REST API Internal DNS CRUD + Domain sinkhole + live DNS query visibility in SQLite
echo "[9/10] Testing REST internal DNS (/api/v1/dns/hosts) + sinkhole + live DNS capture..."
ip netns exec ns-lan curl -sf -X POST http://10.100.0.10:8265/api/v1/dns/hosts \
  -H 'Content-Type: application/json' -d '{"domain":"nas.lan","ip":"10.100.0.55"}' >/dev/null
NAS_IP=$(ip netns exec ns-lan dig +short @10.100.0.10 nas.lan | tail -n1)
[[ "${NAS_IP}" == "10.100.0.55" ]] \
  && pass "Internal DNS record nas.lan resolved to ${NAS_IP}" \
  || fail "Internal DNS failed: expected 10.100.0.55, got '${NAS_IP}'"

ip netns exec ns-lan curl -sf -X POST http://10.100.0.10:8265/api/v1/rules/domains \
  -H 'Content-Type: application/json' -d '{"domain":"bad.test"}' >/dev/null
BAD_IP=$(ip netns exec ns-lan dig +short @10.100.0.10 bad.test | tail -n1)
[[ "${BAD_IP}" == "0.0.0.0" ]] \
  && pass "REST POST /api/v1/rules/domains sinkholed bad.test -> 0.0.0.0" \
  || fail "REST sinkhole failed: got '${BAD_IP}'"
ip netns exec ns-lan dig +short @10.100.0.10 good.test >/dev/null

# Wait for 1.5s batched SQLite WAL flush + collector tick
sleep 3

DNS_JSON=$(ip netns exec ns-lan curl -sf http://10.100.0.10:8265/api/v1/dns/queries?limit=20 || true)
[[ "${DNS_JSON}" == *'"domain":"bad.test"'* && "${DNS_JSON}" == *'"action":"sinkholed"'* ]] \
  && pass "Live DNS queries captured into SQLite WAL (bad.test sinkholed)" \
  || fail "Expected bad.test in /api/v1/dns/queries, got: ${DNS_JSON}"

# 10. Live conntrack flows, LAN device discovery, and audit trail in SQLite WAL
echo "[10/10] Testing live flows, device discovery, and audit log..."
FLOWS_JSON=$(ip netns exec ns-lan curl -sf http://10.100.0.10:8265/api/v1/flows?limit=20 || true)
[[ "${FLOWS_JSON}" == *'"dst_ip":"10.200.0.2"'* ]] \
  && pass "Live conntrack flows captured into SQLite WAL" \
  || fail "Expected 10.200.0.2 in /api/v1/flows, got: ${FLOWS_JSON}"

DEV_JSON=$(ip netns exec ns-lan curl -sf http://10.100.0.10:8265/api/v1/devices || true)
[[ "${DEV_JSON}" == *'"ip":"10.100.0.20"'* ]] \
  && pass "LAN device 10.100.0.20 discovered automatically" \
  || fail "Expected 10.100.0.20 in /api/v1/devices, got: ${DEV_JSON}"

AUDIT_JSON=$(ip netns exec ns-lan curl -sf http://10.100.0.10:8265/api/v1/audit?limit=20 || true)
[[ "${AUDIT_JSON}" == *'"action":"block_ip"'* && "${AUDIT_JSON}" == *'"action":"block_domain"'* ]] \
  && pass "Audit log persisted REST mutations in SQLite WAL" \
  || fail "Expected audit entries, got: ${AUDIT_JSON}"

echo "=== NulKast-FW Phase 3 Inline NFQUEUE IDS/IPS & Feed Importer Tests ==="

# Start a self-signed HTTPS server on ns-wan:443 to test real TLS 1.3 ClientHello SNI + FoxIO JA4
openssl req -x509 -newkey rsa:2048 -keyout /tmp/wan.key -out /tmp/wan.crt \
  -days 1 -nodes -subj "/CN=evil.test" >/dev/null 2>&1
ip netns exec ns-wan python3 -c "
import socket, ssl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
socket.setdefaulttimeout(3)
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
trap 'kill "${API_PID}" "${TLS_PID}" 2>/dev/null || true; cleanup' EXIT
sleep 0.5

# 11. Multi-vendor feed import (Suricata TLS rule for evil.test + JA4 + Adblock + IP)
echo "[11/13] Testing multi-vendor feed importer (IP, Domain, JA4, Suricata subset)..."
SURI_RESP=$(ip netns exec ns-lan curl -sf -X POST http://10.100.0.10:8265/api/v1/feeds/import \
  -H 'Content-Type: application/json' \
  -d '{"format":"suricata","content":"drop tls any any -> any 443 (msg:\"Block Evil SNI\"; tls.sni; content:\"evil.test\"; nocase; sid:900001;)\nalert tcp any any -> any any (msg:\"Legacy\"; content:\"x\"; pcre:\"/y/\"; sid:900002;)","apply":false}' || true)
[[ "${SURI_RESP}" == *'"imported":1'* && "${SURI_RESP}" == *'"skipped_unsupported":1'* ]] \
  && pass "Suricata subset imported 1 modern rule and cleanly skipped 1 legacy PCRE rule" \
  || fail "Suricata import failed: ${SURI_RESP}"

JA4_RESP=$(ip netns exec ns-lan curl -sf -X POST http://10.100.0.10:8265/api/v1/feeds/import \
  -H 'Content-Type: application/json' \
  -d '{"format":"ja4","content":"t13d1516h2_8daaf6152771_e5627efa2ab1,CobaltStrike","apply":false}' || true)
[[ "${JA4_RESP}" == *'"imported":1'* ]] \
  && pass "JA4/SSLBL hash feed imported cleanly" \
  || fail "JA4 import failed: ${JA4_RESP}"

# 12. Real-packet NFQUEUE TLS SNI + FoxIO JA4 inspection (IDS ALERT -> IPS DROP)
echo "[12/13] Testing live NFQUEUE TLS SNI + FoxIO JA4 (IDS alert -> IPS inline drop)..."
TLS_OK=$(ip netns exec ns-lan curl -skf --max-time 3 --resolve evil.test:443:10.200.0.2 https://evil.test/ || true)
[[ "${TLS_OK}" == "tls-ok" ]] \
  && pass "IDS ALERT mode allowed TLS handshake to evil.test while inspecting inline" \
  || fail "Expected tls-ok in ALERT mode, got '${TLS_OK}'"

sleep 2
ALERTS_JSON=$(ip netns exec ns-lan curl -sf http://10.100.0.10:8265/api/v1/alerts?limit=20 || true)
[[ "${ALERTS_JSON}" == *'evil.test'* && "${ALERTS_JSON}" == *'JA4=t1'* ]] \
  && pass "Live NFQUEUE captured TLS SNI 'evil.test' + FoxIO JA4 fingerprint in SQLite WAL!" \
  || fail "Expected evil.test + JA4 alert, got: ${ALERTS_JSON}"

# Promote to IPS DROP mode via 1-click REST endpoint
ip netns exec ns-lan curl -sf -X POST http://10.100.0.10:8265/api/v1/ids/mode \
  -H 'Content-Type: application/json' -d '{"mode":"drop"}' >/dev/null

if ip netns exec ns-lan curl -skf --max-time 2 --resolve evil.test:443:10.200.0.2 https://evil.test/ >/dev/null 2>&1; then
  fail "IPS DROP mode did NOT block TLS ClientHello for evil.test!"
else
  pass "IPS DROP mode dropped TLS ClientHello for evil.test inline via NFQUEUE!"
fi

TLS_GOOD=$(ip netns exec ns-lan curl -skf --max-time 3 --resolve good.test:443:10.200.0.2 https://good.test/ || true)
[[ "${TLS_GOOD}" == "tls-ok" ]] \
  && pass "Legitimate TLS SNI (good.test) still passed cleanly in IPS mode" \
  || fail "Legitimate good.test TLS handshake failed in IPS mode!"

# 13. Live DNS-bypass detection & inline drop (LAN -> external WAN:53)
echo "[13/13] Testing live DNS-bypass detection & inline drop..."
ip netns exec ns-lan dig +tries=1 +time=1 @10.200.0.2 bypass.test >/dev/null 2>&1 || true
sleep 2
ALERTS_JSON2=$(ip netns exec ns-lan curl -sf http://10.100.0.10:8265/api/v1/alerts?limit=20 || true)
[[ "${ALERTS_JSON2}" == *'"category":"dns_bypass"'* && "${ALERTS_JSON2}" == *'"indicator":"bypass.test"'* && "${ALERTS_JSON2}" == *'"action":"dropped"'* ]] \
  && pass "Live DNS-bypass (bypass.test -> 10.200.0.2:53) detected & dropped inline!" \
  || fail "Expected dns_bypass dropped alert, got: ${ALERTS_JSON2}"

echo "=== ALL 13 PHASE 1 + PHASE 2 + PHASE 3 LAB TESTS PASSED ==="
