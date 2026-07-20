# proxy-machine (Go)

A single-binary proxy machine: harvest proxy candidates by port-scanning, **validate**
them by proxying through each (origin ≠ self-IP), **store** survivors in SQLite, and
**serve** them via an HTTP API, a rotating HTTP/HTTPS relay (CONNECT tunneling), and a
client-facing SOCKS5 listener.

## Pipeline

```
scan (port scanner) ──► _scan_results ──┐
                                        ▼
public proxy lists ───────────►  checker (background loop)
stored proxies (recheck) ─────►   • validate: GET httpbin.org/ip through each proxy,
                                    keep only those whose origin (every comma component)
                                    ≠ our self-IP  (anonymous + working)
                                  • persist survivors → per-type tables (http/https/socks4/socks5)
                                  • prune proxies that no longer validate
                                  • consume _scan_results
                                        │
          ┌───────────────────────┼───────────────────────────┐
          ▼                       ▼                           ▼
  API (:8000)          HTTP/HTTPS relay (:3333)      SOCKS5 listener (:1080)
  GET /proxy/{type}    forwards HTTP + tunnels        clients dial socks5://;
  ?time=&minutes=      HTTPS (CONNECT) through a      tunnels through the same
  from per-type        rotating, health-ranked        rotating upstreams. All
  tables               validated upstream (dialed     three loopback by default.
                       http/https/socks4/socks5); bounded
                       failover + circuit breaker.
```

## Build & run

```sh
go build -o proxymachine .

# Service (checker loop + API + HTTP/HTTPS relay + SOCKS5 listener):
./proxymachine --dbPath data.db

# Use it — every request egresses through a rotating validated upstream:
curl -x http://127.0.0.1:3333 http://httpbin.org/ip        # HTTP via relay
curl -x http://127.0.0.1:3333 https://httpbin.org/ip       # HTTPS via relay (CONNECT)
curl --socks5-hostname 127.0.0.1:1080 https://httpbin.org/ip  # via SOCKS5 listener

# One-shot port scan → _scan_results (the checker validates them next cycle):
./proxymachine scan -cidr 192.0.2.0/24 -port 8080,3128 --dbPath data.db
```

The scan probes each `ip:port`. If the DB already holds validated **socks4** proxies it
egresses **through** one (anonymous); otherwise — including every fresh install, since no
component currently populates the socks4 table — it falls back to a **direct** TCP probe
so it can bootstrap. IPv6 CIDRs are rejected; expansion is streamed and capped
(`-maxHosts`, default 1,048,576) so a wide range can't OOM.

## Configuration

Flags override an optional `--config` JSON/INI file, which overrides defaults. The INI
form accepts a `[database] path = …` section key.

| Flag | Default | Meaning |
|------|---------|---------|
| `--dbPath` | `data.db` | SQLite path |
| `--workers` | `50` | validation worker pool size |
| `--timeout` | `30s` | total per-proxy validation timeout (list/IP fetch and per-proxy check) |
| `--connectTimeout` | `5s` | connect (+SOCKS handshake) timeout per proxy — dead proxies fail fast |
| `--checkInterval` | `60s` | background re-validation cadence |
| `--maxProxyAge` | `24h` | drop proxies not re-validated within this window (0 disables) |
| `--maxRecheckInterval` | `15m` | cap on adaptive per-proxy recheck cadence (0 = recheck every cycle) |
| `--honeypot` | `true` | reject proxies that tamper with (inject into) HTTP responses |
| `--relayAddr` | `127.0.0.1:3333` | HTTP relay bind (forwards HTTP + tunnels HTTPS via CONNECT) |
| `--apiAddr` | `127.0.0.1:8000` | API bind |
| `--socksAddr` | `127.0.0.1:1080` | client SOCKS5 listener bind (CONNECT + UDP ASSOCIATE; `off` to disable) |
| `--maxFailover` | `5` | max upstream proxies tried per request/tunnel |
| `--chainLength` | `1` | route each tunnel through N chained proxies (extra anonymity) |
| `--stickyHeader` | _(off)_ | request header for session affinity (pins a session to an upstream) |
| `--stickyTTL` | `10m` | sliding idle lifetime of a sticky-session pin |
| `--sources` | _(built-in)_ | comma-separated proxy-list URLs (replaces the built-in set) |
| `--proxyUser` / `--proxyPass` | _(off)_ | require auth on the relay (Basic) **and** SOCKS5 (user/pass) |
| `--maxHosts` | `1048576` | (scan) cap on expanded host IPs |

A ready-to-edit [`config.example.json`](config.example.json) lists every field; pass it
with `--config config.example.json`.

## Proxy sources

The checker harvests candidates from re-verified public lists (HTTP/SOCKS4/SOCKS5), then
validates every one before storing it. The built-in set is `publicProxyURLs` in
[`checker/checker.go`](checker/checker.go); override it without recompiling via
`--sources url1,url2` (or a `"sources": [...]` config array). Each source's type is inferred
from its URL. The parser normalizes each line — bare `ip:port`, `scheme://ip:port`, and
trailing columns are all accepted, and junk lines are dropped.

**On "https" sources:** there is no usable public list of true *TLS-to-proxy* (https)
proxies — files named `…-https.txt` contain plaintext HTTP proxies that support `CONNECT`,
which belong in the http pool. Any validated **http/socks** proxy already carries HTTPS
traffic: the client (or the relay) sends `CONNECT host:443` to the proxy, the proxy opens a
raw tunnel, and end-to-end TLS runs **inside** that tunnel — the proxy never sees the
plaintext. That's why `/proxy/https` (dial-scheme = TLS-to-proxy) is legitimately sparse
while http/socks proxies are your HTTPS-capable pool.

## API

`GET /proxy/{type}` where `type` ∈ `http | https | socks4 | socks5`. Here `type` is the
**dial scheme** of the proxy, not its capability. `https` means a *TLS-to-proxy* server
(you speak TLS to the proxy itself) — those are rare in the wild, so **`/proxy/https` is
normally near-empty**. This is expected, not a bug: public "https proxy" lists actually
contain plaintext **http** proxies that support `CONNECT`, so they live in `/proxy/http`.
For **HTTPS traffic**, use any `http`/`socks` proxy — the relay auto-tunnels HTTPS through
them via `CONNECT` (see `checker/https_smoke_test.go` for the proof).

- `time` — max response time in **seconds** (float), e.g. `?time=1.5`
- `minutes` — max age since last check (default `30`; `0` disables)
- `anon` — anonymity tier filter: `elite` (no proxy-revealing headers), `anonymous`
  (proxy detectable but your IP hidden), or `unknown` (validated but not classified —
  the header-reflecting endpoint wasn't reached). Transparent proxies (that leak your IP)
  are never stored. Empty = any tier.
- `country` — 2-letter country code (e.g. `US`), and `asn` — case-insensitive substring of
  the `AS<n> <org>` string (e.g. `asn=cloudflare`). Both use the background geo enrichment
  (only enriched proxies match).
- `format` — `json` (array of `{proxy,response_time,last_checked,anon}`, fastest first),
  `text`, `csv`, `curl` (paste-ready `curl -x` lines), or `proxychains` (`[ProxyList]` lines)
- `pick=1` — return a single round-robin proxy; `session=ID` pins that session to one proxy
  (sliding TTL) for a stable egress IP; add `rotate=1` to force a fresh pick

`GET /proxy.pac` serves a browser proxy-auto-config pointing at the relay with the fastest
fresh http proxies as fallbacks.

An empty match is `200` with an empty body. `GET /` serves HTML docs. Probes: `GET /health`
→ `ok` (liveness, always 200); `GET /ready` → `200` once ≥1 validated upstream exists, else
`503` (readiness — use as a k8s readinessProbe / LB gate).

Observability: `GET /stats` returns JSON `{proxies:{<type>:count}, relay:{…counters}}`;
`GET /metrics` returns the same in Prometheus text format (`proxymachine_proxies`,
`proxymachine_relay_requests_total`, `…_failures_total`, `…_upstream_attempts_total`);
`GET /upstreams` lists each relay upstream's live health (ewma latency, consecutive fails,
circuit state); `GET /ready` gates on ≥1 validated upstream.

## Security defaults

The API, HTTP relay and SOCKS5 listener all bind to **loopback** by default — a fresh
install is **not** an open proxy. To expose the relay/SOCKS on a network, widen the bind
(e.g. `--relayAddr 0.0.0.0:3333`) **and** set `--proxyUser`/`--proxyPass`: relay requests
then need Basic `Proxy-Authorization` and SOCKS5 clients need RFC 1929 username/password
(the credential is hop-by-hop-stripped / never forwarded upstream). Binding either to a
non-loopback address **without** `--proxyUser` logs a loud open-proxy warning. The relay
caps a request body at 32 MiB (returns `413` above it). Disable the SOCKS5 listener
entirely with `--socksAddr off`.

## Docker

```sh
docker build -t proxymachine .
# Safe default (loopback-only, so bind-mount a data volume and exec in, or expose explicitly):
docker run -p 3333:3333 -p 8000:8000 -p 1080:1080 -v pm:/data proxymachine \
  --relayAddr 0.0.0.0:3333 --apiAddr 0.0.0.0:8000 --socksAddr 0.0.0.0:1080 \
  --proxyUser u --proxyPass p
```

The image is a static single binary on Alpine (CGO-free). Exposing on `0.0.0.0` **requires**
`--proxyUser`/`--proxyPass` or you run an open proxy.

## Tests

```sh
go test -race ./...
```

## Notes / limitations

- The relay forwards plaintext HTTP **and** tunnels HTTPS/any-TCP via `CONNECT`. A
  client-facing **SOCKS5** listener (CONNECT only;
  no BIND/UDP) tunnels through the same upstreams. Both dial upstream http/https/socks4/socks5
  proxies with the correct scheme; an https upstream's TLS hop is not cert-verified (free
  proxies rarely present valid certs) — the client's end-to-end TLS inside the tunnel is
  unaffected and still authenticates the real target.
- Upstream selection is **health-ranked**: alive/unknown proxies rotate (IP diversity);
  proven-slow ones are demoted and a proxy with a run of failures trips a **circuit
  breaker** (skipped for a cooldown). Each request tries at most `--maxFailover` upstreams,
  and each attempt is time-bounded so a hanging dead proxy can't eat the request budget.
- **Session affinity** (`--stickyHeader`): relay/CONNECT requests carrying the header are
  pinned to the upstream they last succeeded through (sliding `--stickyTTL`), so sites that
  bind a session to the egress IP keep the same IP. Failover still applies if the pin dies.
- **Proxy chaining** (`--chainLength N`): each tunnel is routed through N distinct proxies in
  sequence (nested CONNECT/SOCKS handshakes) for extra anonymity — slower and more fragile.
- **Honeypot detection** (`--honeypot`): a proxy that rewrites/injects into plaintext HTTP
  responses is rejected during validation (TLS-MITM proxies already fail target-cert checks).
- **Adaptive recheck**: a proxy's re-validation interval grows with each consecutive success
  (up to `--maxRecheckInterval`), so stable proxies aren't re-checked every cycle.
- **SOCKS5 UDP ASSOCIATE**: the listener relays UDP (DNS/QUIC). NOTE: UDP egresses **directly**
  from this host (upstreams are TCP-only) — it is not anonymized through the proxy pool.
- **Integration**: `GET /proxy.pac`, and `?format=csv|curl|proxychains`; `?pick=1`/`?session=`
  for on-demand rotation.
- socks4/4a proxies are validated (dialed through with the `pkg/socks` client, since
  net/http can't proxy socks4) and served/egressed like the other types.
- Failover replays only idempotent methods (GET/HEAD/OPTIONS/TRACE/PUT/DELETE); POST/
  PATCH are not retried across upstreams, to avoid duplicate side effects.
- SQLite is opened with a single connection (`SetMaxOpenConns(1)`) so concurrent
  checker-writes and API/relay-reads can't race to `SQLITE_BUSY`.
