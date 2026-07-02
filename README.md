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
| `--workers` | `4` | validation worker pool size |
| `--timeout` | `30s` | per-request timeout (list/IP fetch and per-proxy check) |
| `--checkInterval` | `60s` | background re-validation cadence |
| `--relayAddr` | `127.0.0.1:3333` | HTTP relay bind (forwards HTTP + tunnels HTTPS via CONNECT) |
| `--apiAddr` | `127.0.0.1:8000` | API bind |
| `--socksAddr` | `127.0.0.1:1080` | client SOCKS5 listener bind (`off` to disable) |
| `--maxFailover` | `5` | max upstream proxies tried per request/tunnel |
| `--proxyUser` / `--proxyPass` | _(off)_ | require auth on the relay (Basic) **and** SOCKS5 (user/pass) |
| `--maxHosts` | `1048576` | (scan) cap on expanded host IPs |

## Proxy sources

The checker harvests candidates from re-verified public lists (HTTP/SOCKS4/SOCKS5), then
validates every one before storing it. The source set is `publicProxyURLs` in
[`checker/checker.go`](checker/checker.go). The parser normalizes each line — bare
`ip:port`, `scheme://ip:port`, and trailing columns are all accepted, and junk lines are
dropped — so adding a new source is just adding its URL.

## API

`GET /proxy/{type}` where `type` ∈ `http | https | socks4 | socks5`:

- `time` — max response time in **seconds** (float), e.g. `?time=1.5`
- `minutes` — max age since last check (default `30`; `0` disables)
- `format` — `json` (array of `{proxy,response_time,last_checked}`, fastest first) or `text`

An empty match is `200` with an empty body. `GET /` serves HTML docs; `GET /health` → `ok`.

Observability: `GET /stats` returns JSON `{proxies:{<type>:count}, relay:{…counters}}`;
`GET /metrics` returns the same in Prometheus text format (`proxymachine_proxies`,
`proxymachine_relay_requests_total`, `…_failures_total`, `…_upstream_attempts_total`).

## Security defaults

The API, HTTP relay and SOCKS5 listener all bind to **loopback** by default — a fresh
install is **not** an open proxy. To expose the relay/SOCKS on a network, widen the bind
(e.g. `--relayAddr 0.0.0.0:3333`) **and** set `--proxyUser`/`--proxyPass`: relay requests
then need Basic `Proxy-Authorization` and SOCKS5 clients need RFC 1929 username/password
(the credential is hop-by-hop-stripped / never forwarded upstream). Binding either to a
non-loopback address **without** `--proxyUser` logs a loud open-proxy warning. The relay
caps a request body at 32 MiB (returns `413` above it). Disable the SOCKS5 listener
entirely with `--socksAddr off`.

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
  breaker** (skipped for a cooldown). Each request tries at most `--maxFailover` upstreams.
- socks4/4a proxies are validated (dialed through with the `pkg/socks` client, since
  net/http can't proxy socks4) and served/egressed like the other types.
- Failover replays only idempotent methods (GET/HEAD/OPTIONS/TRACE/PUT/DELETE); POST/
  PATCH are not retried across upstreams, to avoid duplicate side effects.
- SQLite is opened with a single connection (`SetMaxOpenConns(1)`) so concurrent
  checker-writes and API/relay-reads can't race to `SQLITE_BUSY`.
