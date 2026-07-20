#!/usr/bin/env bash
# Smoke-test the running proxy-machine: relay (HTTP + HTTPS/CONNECT), SOCKS5 listener,
# rotation, export formats and API — against REAL IP/ASN endpoints so you can see the exit
# IP + ASN/ISP/geo (and confirm it differs from your real IP = anonymity works).
#
# Usage: bash smoke.sh
set -uo pipefail
RELAY=127.0.0.1:3333
SOCKS=127.0.0.1:1080
API=http://127.0.0.1:8000
CT=15   # per-request curl timeout

# Pretty-print JSON if python3 is around, else raw.
pp() { python3 -m json.tool 2>/dev/null || cat; }
hr() { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }

hr "Your REAL IP (direct, no proxy)"
MYIP=$(curl -s -m $CT https://api.ipify.org); echo "${MYIP:-<no network?>}"

hr "Wait for the pool to be ready (>=1 validated upstream)"
for i in $(seq 1 60); do
  [ "$(curl -s -o /dev/null -w '%{http_code}' -m 5 $API/ready)" = 200 ] && { echo "ready"; break; }
  sleep 2; printf '.'
done

hr "API /stats (proxy counts + relay counters)"
curl -s -m $CT $API/stats | pp

# try a request through a proxy up to N times (free proxies flap; relay fails over within a
# request, but the picked exit can still be dead/slow — retry a few times).
try() { local n=$1; shift; local out; for _ in $(seq 1 "$n"); do out=$("$@" 2>/dev/null); [ -n "$out" ] && { echo "$out"; return 0; }; done; echo "(no response after $n tries)"; }

hr "HTTPS through the RELAY (CONNECT)  ->  ipwho.is (asn/isp/country) [TLS = injection-proof]"
try 4 curl -s -m $CT -x http://$RELAY https://ipwho.is/ | pp

hr "SOCKS5 listener  ->  ipinfo.io"
try 4 curl -s -m $CT --socks5-hostname $SOCKS https://ipinfo.io/json | pp

hr "PLAINTEXT-HTTP through relay  ->  ip-api.com  [may return an INJECTED page — free-proxy hazard]"
try 4 curl -s -m $CT -x http://$RELAY http://ip-api.com/json | pp

hr "ROTATION over HTTPS: 6 exits (should differ from $MYIP and from each other)"
for i in $(seq 1 6); do
  echo -n "  #$i exit: "
  try 3 curl -s -m $CT -x http://$RELAY https://api.ipify.org
done

hr "STICKY session: same ?session should hold one exit IP; API pick"
S=sess-$RANDOM
for i in 1 2 3; do curl -s -m 5 "$API/proxy/http?minutes=0&format=text&session=$S" ; done

hr "EXPORT formats"
echo "-- proxychains --"; curl -s -m 5 "$API/proxy/http?minutes=0&format=proxychains" | head -3
echo "-- curl --";        curl -s -m 5 "$API/proxy/socks5?minutes=0&format=curl" | head -3
echo "-- /proxy.pac --";  curl -s -m 5 "$API/proxy.pac" | head -2

hr "UPSTREAM health (top 3)"
curl -s -m 5 $API/upstreams | python3 -c 'import sys,json; d=json.load(sys.stdin); print(json.dumps(d[:3], indent=2))' 2>/dev/null || curl -s -m 5 $API/upstreams | head -c 400

hr "Done. If an exit IP == $MYIP, that proxy leaked (should have been rejected as transparent)."
