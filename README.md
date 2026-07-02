# proxy-machine (Go)

A single-binary Go port of proxy-machine: harvest proxy candidates by port-scanning,
**validate** them by proxying through each (origin ≠ self-IP), **store** survivors in
SQLite, and **serve** them via an HTTP API and a rotating HTTP relay. This is the primary
implementation; the original Python version lives in [`python/`](python) (legacy)
and is the behavioral spec.

## Pipeline

```
scan (port scanner) ──► _scan_results ──┐
                                        ▼
public proxy lists ───────────►  checker (background loop)
stored proxies (recheck) ─────►   • validate: GET httpbin.org/ip through each proxy,
                                    keep only those whose origin (every comma component)
                                    ≠ our self-IP  (anonymous + working)
                                  • persist survivors → per-type tables (http/https/socks5)
                                  • prune proxies that no longer validate
                                  • consume _scan_results
                                        │
                  ┌─────────────────────┴───────────────────────┐
                  ▼                                              ▼
        API (:8000, loopback)                  HTTP relay (:3333, loopback)
        GET /proxy/{type}?time=&minutes=        forwards client requests through a rotating,
        served from the per-type tables         validated upstream proxy, dialed with its own
                                                scheme (http/https/socks5); refreshed every 15s
```

## Build & run

```sh
go build -o proxymachine .

# Service (checker loop + API + relay):
./proxymachine --dbPath data.db

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
form accepts a `[database] path = …` section key (matching `python/config.ini`).

| Flag | Default | Meaning |
|------|---------|---------|
| `--dbPath` | `data.db` | SQLite path |
| `--workers` | `4` | validation worker pool size |
| `--timeout` | `30s` | per-request timeout (list/IP fetch and per-proxy check) |
| `--checkInterval` | `60s` | background re-validation cadence |
| `--relayAddr` | `127.0.0.1:3333` | relay bind |
| `--apiAddr` | `127.0.0.1:8000` | API bind |
| `--proxyUser` / `--proxyPass` | _(off)_ | require Basic `Proxy-Authorization` on the relay |
| `--maxHosts` | `1048576` | (scan) cap on expanded host IPs |

## Proxy sources

The checker harvests candidates from re-verified public lists (HTTP/SOCKS5), then validates
every one before storing it. The Go set is `publicProxyURLs` in
[`checker/checker.go`](checker/checker.go); the Python set is the tracked
[`python/urls.txt`](python/urls.txt) (consumed by `checker.py -list`). Both
parsers normalize each line — bare `ip:port`, `scheme://ip:port`, and trailing columns are
all accepted, and junk lines are dropped — so adding a new source is just adding its URL.

## API

`GET /proxy/{type}` where `type` ∈ `http | https | socks5` (`socks4` is accepted but
reserved — nothing populates it yet, so it always returns an empty list):

- `time` — max response time in **seconds** (float), e.g. `?time=1.5`
- `minutes` — max age since last check (default `30`; `0` disables)
- `format` — `json` (array of `{proxy,response_time,last_checked}`, fastest first) or `text`

An empty match is `200` with an empty body. `GET /` serves HTML docs; `GET /health` → `ok`.

## Security defaults

The relay and API bind to **loopback** by default — a fresh install is **not** an open
proxy. To expose the relay on a network, set `--relayAddr 0.0.0.0:3333` **and**
`--proxyUser`/`--proxyPass`; every relay request then needs Basic `Proxy-Authorization`
(the credential is hop-by-hop-stripped and never forwarded upstream). Binding to a
non-loopback address **without** `--proxyUser` logs a loud open-proxy warning. The relay
caps a request body at 32 MiB (returns `413` above it).

## Tests

```sh
go test -race ./...
```

## Notes / limitations

- The relay is an HTTP forward proxy (matches `python/http-proxy-relay.py`); it
  does not implement CONNECT/HTTPS tunneling of client traffic. It *does* dial upstream
  http/https/socks5 proxies with the correct scheme.
- socks4 proxies are harvested by the scanner but not validated/served by the Go pipeline
  (net/http cannot proxy socks4) — a documented follow-up needing a manual SOCKS4 client.
- Failover replays only idempotent methods (GET/HEAD/OPTIONS/TRACE/PUT/DELETE); POST/
  PATCH are not retried across upstreams, to avoid duplicate side effects.
- SQLite is opened with a single connection (`SetMaxOpenConns(1)`) so concurrent
  checker-writes and API/relay-reads can't race to `SQLITE_BUSY`.
