#!/usr/bin/env bash
# Validate that stock openvpn in split-tunnel mode leaves the Mac's network
# stack alone — the invariant vpnp is built on. Run this against YOUR
# endpoint before trusting the approach:
#
#   sudo bash docs/validate-direct-openvpn.sh
#
# Prerequisites:
#   - config/vpn.ovpn in place (or CFG=<path>)
#   - VPN_TEST_URL set in .env or the environment: a VPN-private HTTPS URL
#     whose hostname resolves to a private IP through the VPN's DNS
#   - the endpoint DNS name must resolve (AWS withdraws it while no target
#     network is associated):  dig +short <random>.<your-cvpn-endpoint-dns>
#   - any OTHER VPN disconnected
#
# Focus: does openvpn keep net.inet.ip.forwarding and the default route
# intact (so apple/container is unaffected) while routing the pushed
# ranges + VPN DNS?
set -uo pipefail

OUT=/tmp/validate-out.txt
exec > >(tee "$OUT") 2>&1   # visible live AND saved to $OUT

OVPN_BIN=${OVPN_BIN:-/opt/homebrew/sbin/openvpn}
# Resolve paths relative to this script's repo (docs/ -> repo root).
SELF_DIR=$(cd "$(dirname "$0")" && pwd)
CFG=${CFG:-"$SELF_DIR/../config/vpn.ovpn"}
if [ -z "${VPN_TEST_URL:-}" ] && [ -f "$SELF_DIR/../.env" ]; then
  VPN_TEST_URL=$(sed -n 's/^VPN_TEST_URL=//p' "$SELF_DIR/../.env" | tail -1)
fi
if [ -z "${VPN_TEST_URL:-}" ]; then
  echo "ERROR: set VPN_TEST_URL (in .env or the environment) to a VPN-private HTTPS URL" >&2
  exit 2
fi
URL=$VPN_TEST_URL
HOST=$(printf '%s' "$URL" | sed -E 's|^https?://([^/:]+).*|\1|')
VPNDNS=${VPNDNS:-10.0.0.2}   # the VPN's DNS server (VPC resolver)
LOG=/tmp/ovpn-validate.log
PIDF=/tmp/ovpn-validate.pid
FAILED=0
pass(){ echo "PASS  $*"; }
fail(){ echo "FAIL  $*"; FAILED=1; }
fwd(){ sysctl net.inet.ip.forwarding; }
defif(){ route -n get default 2>/dev/null | awk '/interface:/{print $2}'; }

echo "== [A] baseline (make sure NO other VPN is connected) =="
echo "  $(fwd)   default iface = $(defif)"
FWD0=$(sysctl -n net.inet.ip.forwarding); DEF0=$(defif)

cleanup(){
  echo "== [D] teardown =="
  [ -f "$PIDF" ] && kill "$(cat "$PIDF")" 2>/dev/null; sleep 2
  echo "  after down: $(fwd)   default iface = $(defif)"
  rm -f "$PIDF"
  chmod 644 "$OUT" "$LOG" 2>/dev/null
  echo "== RESULT: $([ $FAILED -eq 0 ] && echo PASS || echo FAIL) =="
}
trap cleanup EXIT

echo "== [B] connecting stock openvpn (split-tunnel, cert auth) =="
# NOTE: AWS profiles have remote-random-hostname; if connect fails with
# "Cannot resolve host address" for a random-prefixed name, pin the IP:
#   IP=$(dig +short "$(openssl rand -hex 4).<your-cvpn-endpoint-dns>" | head -1)
#   ... --config "$CFG" --remote "$IP" 443 udp ...
# (vpnp does this pinning automatically.)
"$OVPN_BIN" --config "$CFG" --daemon --log "$LOG" --writepid "$PIDF" --verb 3 --connect-timeout 20
for i in $(seq 1 30); do
  grep -q "Initialization Sequence Completed" "$LOG" 2>/dev/null && break
  grep -qE "AUTH_FAILED|TLS Error|Exiting|Cannot allocate|ERROR:" "$LOG" 2>/dev/null && break
  sleep 1
done
if ! grep -q "Initialization Sequence Completed" "$LOG"; then
  fail "openvpn did not connect — last log lines:"; tail -15 "$LOG"; exit 1
fi
pass "stock openvpn connected (no patch, cert auth)"

echo "== [C] invariants WHILE CONNECTED =="
echo "  $(fwd)   default iface = $(defif)"
FWD1=$(sysctl -n net.inet.ip.forwarding); DEF1=$(defif)
[ "$FWD1" = "$FWD0" ] && pass "net.inet.ip.forwarding unchanged ($FWD0 -> $FWD1)" || fail "forwarding CHANGED: $FWD0 -> $FWD1 (the container-breaker)"
[ "$DEF1" = "$DEF0" ] && pass "default route still via $DEF1 (not the tunnel)" || fail "default route moved: $DEF0 -> $DEF1"
if netstat -rn -f inet | grep -qE '(^| )10(\.0)?/16|^10\.0\.0\.0'; then
  pass "10.0.0.0/16 routed via the tunnel"; netstat -rn -f inet | grep -E '(^| )10(\.0)?/16|^10\.0\.0\.0' | sed 's/^/    /'
else fail "no 10.0.0.0/16 route installed (different pushed range? check $LOG)"; fi

echo "== VPN DNS + routed HTTPS =="
PRIV=$(dig +short +time=5 @"$VPNDNS" "$HOST" 2>/dev/null | grep -E '^10\.' | head -1)
if [ -n "$PRIV" ]; then
  pass "VPN DNS $VPNDNS resolved $HOST -> $PRIV"
  CODE=$(curl -s -m 15 -o /dev/null -w '%{http_code}' --resolve "$HOST:443:$PRIV" "$URL")
  [ "$CODE" = "200" ] && pass "HTTPS GET through the tunnel -> $CODE" || fail "HTTPS GET -> $CODE"
else fail "VPN DNS did not resolve $HOST to a 10.x address"; fi
