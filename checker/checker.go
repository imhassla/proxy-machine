// Package checker manages proxy validation using a bounded worker pool,
// public IP detection, and public proxy list fetching.
package checker

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"proxymachine/config"
	"proxymachine/db"
	"proxymachine/pkg/socks"
)

// maxListBytes caps how much of a public proxy-list response we read, so a single
// hostile/huge source can't OOM the checker.
const maxListBytes = 8 << 20 // 8 MiB

// canary is a PLAINTEXT-HTTP integrity probe: fetch url through the proxy and check the body
// is what it should be. A content-injecting proxy / captive portal returns its own HTML
// instead → ok() fails → the proxy is rejected. Fetched over http (not https) precisely
// because injection happens on plaintext, which our https validation can't observe.
type canary struct {
	url string
	ok  func(body string) bool
}

// honeypotCanaries are tried in order; the FIRST that responds (200) decides. amazonaws /
// icanhazip return just the caller's IP over plain HTTP and are highly reliable, so the
// check rarely no-ops (the earlier httpbin-only canary was often unreachable through a proxy
// and thus toothless). A captive portal returns HTML → not a valid IP → tampering.
var honeypotCanaries = []canary{
	{"http://checkip.amazonaws.com", isPlainIP},
	{"http://icanhazip.com", isPlainIP},
	{"http://httpbin.org/base64/cHJveHltYWNoaW5lLWNhbmFyeQ==", func(b string) bool { return strings.TrimSpace(b) == "proxymachine-canary" }},
}

// isPlainIP reports whether body is a single line that parses as an IP (what a clean IP-echo
// returns) — false for the HTML an injector/captive-portal serves.
func isPlainIP(body string) bool {
	return net.ParseIP(strings.TrimSpace(body)) != nil
}

// userAgent is sent on every checker HTTP request. Go's default "Go-http-client/1.1" is
// widely blocked by CDNs/anti-bot gateways (e.g. httpbin returns 503 to it while curl gets
// 200) — a browser-like UA gets the harvest/self-IP requests through.
const userAgent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"

var (
	// publicIPURLs / proxyTestURLs are tried IN ORDER with failover, so one flaky provider
	// (httpbin 503s constantly) can't stall the whole pipeline. Self-IP endpoints echo our
	// own address; proxy-test endpoints echo the ORIGIN as seen through the proxy (compared
	// != self-IP for anonymity). httpbin's /ip also reflects the X-Forwarded-For chain,
	// which catches transparent-proxy leaks — kept in the list for that.
	publicIPURLs = []string{
		"https://api.ipify.org",
		"https://checkip.amazonaws.com",
		"https://icanhazip.com",
		"https://ifconfig.me/ip",
		"https://httpbin.org/ip",
	}
	// The anonymity classifier MUST run over PLAINTEXT http: only when the proxy FORWARDS an
	// http request can it add Via/X-Forwarded-For that the target reflects — over https the
	// proxy CONNECT-tunnels the request inside TLS and cannot touch headers, so every proxy
	// would look "elite" (a false positive). So http://httpbin.org/get is first (reflects
	// headers → real elite/anonymous/transparent tier). The https IP-echoes are liveness
	// fallbacks only (origin != self, but tier left "unknown") for when the plaintext probe
	// is unreachable/injected.
	proxyTestURLs = []string{
		"http://httpbin.org/get",
		"https://api.ipify.org",
		"https://checkip.amazonaws.com",
	}
	// publicProxyURLs are re-verified public lists (live + substantial + maintained as of
	// 2026-06). Each source's TYPE is inferred from its URL by getProxyType. The checker
	// validates http/socks5/socks4 (see testableTypes). proxifly serves "scheme://ip:port",
	// which normalizeProxyLine strips.
	publicProxyURLs = []string{
		// http (bare ip:port)
		"https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
		"https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-http.txt",
		"https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt",
		"https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
		// http (scheme://ip:port — normalized)
		"https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/http/data.txt",
		// NOTE: no public "https proxy" list is included. Files named proxies-https.txt
		// actually contain plaintext HTTP proxies that merely SUPPORT CONNECT/HTTPS tunneling
		// — they are not TLS-to-proxy servers, so validating them as type=https (a TLS
		// handshake to the proxy) fails for essentially all of them. Such proxies belong in
		// the http pool, and http proxies already serve HTTPS traffic via CONNECT (the relay
		// does this automatically). The type=https path (with InsecureSkipVerify on the proxy
		// hop) remains for genuine TLS-to-proxy proxies (e.g. found by the scanner), which
		// are rare in the wild — so /proxy/https is legitimately sparse. See
		// checker/https_smoke_test.go for the proof.
		// socks5 (typed via getProxyType on the URL)
		"https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
		"https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks5.txt",
		"https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
		"https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/socks5/data.txt",
		"https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
		// socks4
		"https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt",
		"https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks4.txt",
		"https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/socks4/data.txt",
		"https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks4.txt",
	}
)

// testableTypes are the proxy types the checker validates and the relay can egress
// through. http/https/socks5 are proxied via http.Transport.Proxy; socks4 (which net/http
// cannot proxy) is validated by dialing the test target THROUGH it with the socks package.
var testableTypes = []string{"http", "https", "socks5", "socks4"}

type proxyJob struct {
	addr    string
	typ     string
	recheck bool // a proxy already in the DB being re-validated (prune it if it now fails)
}

type checkResult struct {
	job  proxyJob
	rt   float64
	anon string
	ok   bool
}

// pruneThreshold is how many CONSECUTIVE failed rechecks a stored proxy must accumulate
// before it's deleted. Free proxies flap, so pruning on a single failure evicts working
// ones and inflates re-harvest churn; a small grace keeps intermittent proxies alive.
const pruneThreshold = 3

// CheckManager orchestrates proxy harvesting, validation, persistence and serving.
type CheckManager struct {
	cfg          *config.Config
	db           *db.DB
	cache        map[string][]string
	mu           sync.RWMutex
	directClient *http.Client

	// recheckFails counts consecutive failed rechecks per "typ|addr" (touched only by the
	// single RunCycle goroutine). A proxy is pruned once it reaches pruneThreshold; any
	// success resets it.
	recheckFails map[string]int

	// Adaptive recheck state (single-RunCycle-goroutine access): streak counts consecutive
	// successes per "typ|addr"; nextRecheck holds when a stored proxy is next due for
	// re-validation. Stable proxies get longer intervals, so they aren't rechecked every
	// cycle. Both are cleared on a failure (recheck next cycle).
	streak      map[string]int
	nextRecheck map[string]time.Time

	// Endpoints used for validation, each a failover list tried in order. Default to the
	// public IP-echo / proxy-list URLs; overridable (e.g. self-hosted echoes, or to point
	// tests at local fakes).
	IPURLs   []string // self-IP echoes (fetched directly)
	TestURLs []string // proxy-test targets (fetched THROUGH each candidate)
	ListURLs []string // public proxy-list sources

	// GeoResolved, if set (wired from the geo enricher in main), returns the lifetime count of
	// geolocated proxy IPs. The checker folds the per-cycle delta into its single cycle-done
	// log line so the enricher needs no separate log stream. Read only by the RunCycle goroutine.
	GeoResolved     func() int64
	lastGeoResolved int64
}

// New creates a new CheckManager with the given config and database.
func New(cfg *config.Config, database *db.DB) *CheckManager {
	if cfg == nil {
		cfg = &config.Config{}
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &CheckManager{
		cfg:          cfg,
		db:           database,
		cache:        make(map[string][]string),
		directClient: &http.Client{Timeout: timeout},
		recheckFails: make(map[string]int),
		streak:       make(map[string]int),
		nextRecheck:  make(map[string]time.Time),
		IPURLs:       publicIPURLs,
		TestURLs:     proxyTestURLs,
		ListURLs:     publicProxyURLs,
	}
}

// Start runs the validation loop until ctx is cancelled: each cycle re-fetches the
// self-IP, gathers candidates (public lists + the scanner's _scan_results + a recheck
// of stored proxies), validates them through a bounded worker pool, PERSISTS survivors
// to the per-type DB tables, prunes proxies that no longer work, consumes the scan
// results, and refreshes the in-memory cache. A cancelled ctx returns nil (graceful).
func (cm *CheckManager) Start(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if cm.cfg == nil {
		return fmt.Errorf("config is required")
	}
	interval := cm.cfg.CheckInterval
	if interval <= 0 {
		interval = 60 * time.Second
	}
	for {
		cm.RunCycle(ctx)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(interval):
		}
	}
}

// RunCycle performs one harvest→validate→persist→prune pass. Errors are logged-by-skip
// (a transient self-IP/DB failure skips this cycle rather than killing the service).
func (cm *CheckManager) RunCycle(ctx context.Context) {
	start := time.Now()
	// Re-fetch the self-IP every cycle: without it we cannot tell a working proxy from
	// one that echoes our own IP, so a failed fetch must SKIP the cycle (not validate),
	// and a later cycle recovers — fixing the permanent-degrade-on-startup failure mode.
	sip, err := cm.fetchPublicIP(ctx)
	if err != nil {
		// This is the silent-stall failure mode: without a self-IP NOTHING gets validated,
		// so make it loud — the operator needs to know the pipeline is blocked on network.
		log.Printf("checker: self-IP fetch FAILED from all %d endpoints (%v) — SKIPPING cycle; no proxies will be validated until this recovers (check network egress)", len(cm.IPURLs), err)
		return
	}

	jobs, scanIPs := cm.gatherCandidates(ctx)
	if len(jobs) == 0 {
		log.Printf("checker: cycle start (self-IP %s): 0 candidates — public lists unreachable and DB empty; nothing to validate", sip)
		cm.deleteScanResults(scanIPs)
		return
	}

	var fresh, recheck int
	for _, j := range jobs {
		if j.recheck {
			recheck++
		} else {
			fresh++
		}
	}
	log.Printf("checker: cycle start (self-IP %s): validating %d candidates (%d from lists/scan, %d re-checks) with %d workers", sip, len(jobs), fresh, recheck, cm.cfg.Workers)

	stored := map[string]int{}
	var okCount, prunedCount, processed int
	var prune = map[string][]string{}
	// Persist each survivor AS IT PASSES (not at end of cycle), so the API/relay see fresh
	// proxies within seconds of startup instead of after the whole multi-minute sweep.
	for r := range cm.validateStream(ctx, sip, jobs) {
		processed++
		key := r.job.typ + "|" + r.job.addr
		if r.ok {
			okCount++
			stored[r.job.typ]++
			delete(cm.recheckFails, key) // success resets the failure streak
			// Adaptive recheck: grow the streak and push the next-due time out.
			cm.streak[key]++
			cm.nextRecheck[key] = time.Now().Add(cm.recheckInterval(cm.streak[key]))
			if cm.db != nil {
				// last_checked at the moment of storing (not cycle start): in a long cycle
				// a cycle-start timestamp would already be stale and get filtered by the
				// API's default age window.
				now := time.Now().UTC().Format("2006-01-02 15:04:05")
				if err := cm.db.StoreProxyTier(r.job.typ, r.job.addr, round2(r.rt), now, r.anon); err != nil {
					log.Printf("checker: store %s %s: %v", r.job.typ, r.job.addr, err)
				}
			}
			// Push newly-stored proxies into the relay cache mid-cycle (silently).
			if okCount%25 == 0 {
				cm.refreshCacheFromDB()
			}
		} else if r.job.recheck && cm.db != nil {
			// A failure resets adaptive state so the proxy is rechecked promptly next cycle.
			delete(cm.streak, key)
			delete(cm.nextRecheck, key)
			// Grace: only prune after pruneThreshold CONSECUTIVE failed rechecks, so a
			// momentarily-flaky proxy isn't evicted (and re-harvested) on one bad cycle.
			cm.recheckFails[key]++
			if cm.recheckFails[key] >= pruneThreshold {
				prune[r.job.typ] = append(prune[r.job.typ], r.job.addr)
				delete(cm.recheckFails, key)
				prunedCount++
			}
		}
	}
	for typ, dead := range prune {
		_ = cm.db.DeleteProxies(typ, dead)
	}
	// Evict adaptive-recheck state for proxies long gone from the DB (retention/prune) so the
	// maps don't accumulate dead keys. A live proxy's nextRecheck is at most
	// MaxRecheckInterval in the future; anything hours in the past is abandoned.
	staleCutoff := time.Now().Add(-24 * time.Hour)
	for k, due := range cm.nextRecheck {
		if due.Before(staleCutoff) {
			delete(cm.nextRecheck, k)
			delete(cm.streak, k)
		}
	}
	// recheckFails can't age out via nextRecheck (a failure deletes the proxy's nextRecheck
	// entry), so evict it separately: a stored proxy still failing rechecks is re-queued every
	// cycle (its nextRecheck was cleared, so it's always "due"), so any recheckFails key NOT in
	// this cycle's job set belongs to a proxy that has left the DB — drop it. Without this the
	// map strands keys for proxies pruned while stuck at 1–2 fails (below pruneThreshold).
	if len(cm.recheckFails) > 0 {
		present := make(map[string]struct{}, len(jobs))
		for _, j := range jobs {
			present[j.typ+"|"+j.addr] = struct{}{}
		}
		for k := range cm.recheckFails {
			if _, ok := present[k]; !ok {
				delete(cm.recheckFails, k)
			}
		}
	}
	// The scanner's candidates have now been classified/validated, so consume them
	// (mirrors checker.py -scan clearing _scan_results) regardless of outcome.
	cm.deleteScanResults(scanIPs)

	// Retention: drop proxies not successfully re-validated within MaxProxyAge, bounding
	// table growth (and next cycle's recheck job count) over long uptime.
	if cm.db != nil && cm.cfg.MaxProxyAge > 0 {
		cutoff := time.Now().UTC().Add(-cm.cfg.MaxProxyAge).Format("2006-01-02 15:04:05")
		if n, err := cm.db.PruneStale(cutoff); err != nil {
			log.Printf("checker: retention prune failed: %v", err)
		} else if n > 0 {
			log.Printf("checker: retention pruned %d proxies older than %s", n, cm.cfg.MaxProxyAge)
		}
	}
	// Keep the geo table bounded to the live pool: drop enrichment rows for proxy IPs that
	// have since left the DB. Without this _geo is insert-only and grows forever (and bloats
	// the enricher's per-cycle full-table scan). Gated on GeoLookup so it's a no-op when the
	// enricher isn't populating _geo at all.
	if cm.db != nil && cm.cfg.GeoLookup {
		if n, err := cm.db.PruneGeoOrphans(); err != nil {
			log.Printf("checker: geo prune failed: %v", err)
		} else if n > 0 {
			log.Printf("checker: pruned %d orphaned geo rows", n)
		}
	}
	// Keep the discovery-attribution count in sync with the live pool: drop rows for proxies
	// that have since been pruned as dead, so "via discover" reflects the currently-live
	// contribution (≤ total) rather than a lifetime tally that only ever grows.
	if cm.db != nil {
		if _, err := cm.db.PruneDiscoveredOrphans(); err != nil {
			log.Printf("checker: discovered prune failed: %v", err)
		}
	}

	cm.refreshCacheFromDB()
	// Fold geo enrichment progress into this one line (the enricher stays silent): show how
	// many proxy IPs it geolocated during this cycle and the running total.
	geoNote := ""
	if cm.GeoResolved != nil {
		cur := cm.GeoResolved()
		geoNote = fmt.Sprintf(", geo +%d (%d total)", cur-cm.lastGeoResolved, cur)
		cm.lastGeoResolved = cur
	}
	log.Printf("checker: cycle done in %s: %d/%d validated OK (http=%d https=%d socks4=%d socks5=%d), %d pruned dead%s",
		time.Since(start).Round(time.Second), okCount, len(jobs),
		stored["http"], stored["https"], stored["socks4"], stored["socks5"], prunedCount, geoNote)
}

// gatherCandidates builds the dedup'd job set for a cycle and the list of scan-result
// ip:ports consumed (to delete afterwards). Sources: public lists (typed), the
// scanner's _scan_results (untyped → tried as each testable type), and stored proxies
// (recheck). A nil/absent DB simply yields fewer sources.
func (cm *CheckManager) gatherCandidates(ctx context.Context) (jobs []proxyJob, scanIPs []string) {
	seen := map[proxyJob]int{} // (addr,typ) → index in jobs
	add := func(addr, typ string, recheck bool) {
		addr = strings.TrimSpace(addr)
		if addr == "" {
			return
		}
		key := proxyJob{addr: addr, typ: typ}
		if i, ok := seen[key]; ok {
			// Already queued. OR the recheck flag UP (never down): a proxy that is both
			// stored AND on a fresh public list must keep recheck=true so it can be
			// pruned if it now fails — public lists are added first, so without this the
			// stored-proxy recheck flag would be lost and dead proxies never pruned.
			if recheck {
				jobs[i].recheck = true
			}
			return
		}
		seen[key] = len(jobs)
		jobs = append(jobs, proxyJob{addr: addr, typ: typ, recheck: recheck})
	}

	// Public lists: typed by URL (http/socks5/socks4). All are validatable now.
	for typ, list := range cm.fetchPublicProxies(ctx) {
		for _, p := range list {
			add(p, typ, false)
		}
	}

	if cm.db != nil {
		// The scanner's open ip:ports — type unknown, so try each testable type.
		if scanIPs, _ = cm.db.GetScanResults(); len(scanIPs) > 0 {
			for _, ipPort := range scanIPs {
				for _, typ := range testableTypes {
					add(ipPort, typ, false)
				}
			}
		}
		// Re-validate already-stored proxies so stale ones get pruned and live ones
		// get a fresh last_checked — but ADAPTIVELY: skip stored proxies not yet due for a
		// recheck (stable ones have a longer interval), unless they also appear on a fresh
		// list above (then they're already queued and validated anyway).
		now := time.Now()
		for _, typ := range testableTypes {
			stored, _ := cm.db.GetProxiesByType(typ)
			for _, p := range stored {
				if cm.cfg.MaxRecheckInterval > 0 {
					if due, ok := cm.nextRecheck[typ+"|"+p]; ok && now.Before(due) {
						continue // not due yet
					}
				}
				add(p, typ, true)
			}
		}
	}
	return jobs, scanIPs
}

// recheckInterval returns the adaptive cadence for a proxy with the given consecutive
// success streak: CheckInterval doubled per success, capped at MaxRecheckInterval.
func (cm *CheckManager) recheckInterval(streak int) time.Duration {
	base := cm.cfg.CheckInterval
	if base <= 0 {
		base = 60 * time.Second
	}
	max := cm.cfg.MaxRecheckInterval
	if max <= 0 {
		return base
	}
	d := base
	for i := 0; i < streak && d < max; i++ {
		d *= 2
	}
	if d > max {
		d = max
	}
	return d
}

// validateStream runs jobs through a bounded worker pool and STREAMS each result on the
// returned channel as it's checked (rather than collecting the whole batch first), so the
// caller can persist survivors in real time — with 100k+ candidates a batch-at-the-end
// approach leaves the DB empty for the entire (very long) cycle. The channel closes when
// every job has been checked (or ctx is cancelled).
func (cm *CheckManager) validateStream(ctx context.Context, sip string, jobs []proxyJob) <-chan checkResult {
	in := make(chan proxyJob)
	go func() {
		defer close(in)
		for _, job := range jobs {
			select {
			case in <- job:
			case <-ctx.Done():
				return
			}
		}
	}()
	return cm.validateStreamChan(ctx, sip, len(jobs), in)
}

// validateStreamChan is validateStream's core over a job CHANNEL (fed continuously), so a
// producer — a cycle's slice, or the discovery scanner streaming open ports as it finds them —
// can pipe jobs in without materializing them first. workerHint caps the pool to the known job
// count when >0 (0 = unknown → use the full configured worker count).
func (cm *CheckManager) validateStreamChan(ctx context.Context, sip string, workerHint int, in <-chan proxyJob) <-chan checkResult {
	workers := cm.cfg.Workers
	if workers <= 0 {
		workers = 1
	}
	if workerHint > 0 && workers > workerHint {
		workers = workerHint
	}
	out := make(chan checkResult, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range in {
				rt, anon, ok := cm.check(ctx, sip, job)
				select {
				case out <- checkResult{job: job, rt: rt, anon: anon, ok: ok}:
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	go func() {
		wg.Wait()
		close(out)
	}()
	return out
}

// ValidateAndStoreStream validates each ip:port arriving on the channel as EVERY testable proxy
// type and stores survivors the moment they pass — continuously, until the channel closes. It
// reuses the exact per-proxy validation of a normal cycle (self-IP check, anonymity tiering,
// honeypot) but skips the cycle's recheck/prune bookkeeping, so it's a pure additive
// discovery path: found → validated (all types) → stored, with no wait for the next cycle.
// Returns the number of (proxy,type) rows stored. Safe to run alongside the background loop.
func (cm *CheckManager) ValidateAndStoreStream(ctx context.Context, ipPorts <-chan string) (int, []string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	sip, err := cm.fetchPublicIP(ctx)
	if err != nil {
		return 0, nil, fmt.Errorf("self-IP fetch failed: %w", err)
	}

	// Fan each incoming ip:port out into one job per testable type.
	in := make(chan proxyJob)
	go func() {
		defer close(in)
		for hp := range ipPorts {
			hp = strings.TrimSpace(hp)
			if hp == "" {
				continue
			}
			for _, typ := range testableTypes {
				select {
				case in <- proxyJob{addr: hp, typ: typ}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	var processed, stored int
	newSet := map[string]struct{}{} // distinct net-new proxy ADDRESSES (for adaptive expansion)
	var netNew []string
	lastLog := time.Now()
	for r := range cm.validateStreamChan(ctx, sip, 0, in) {
		processed++
		// Periodic progress so a long streaming pass isn't a silent black box.
		if time.Since(lastLog) >= 30*time.Second {
			log.Printf("discover: validated %d candidates, stored %d (%d net-new) so far", processed, stored, len(netNew))
			lastLog = time.Now()
		}
		if !r.ok || cm.db == nil {
			continue
		}
		// Attribution: a survivor not already in its type table is a NET-NEW proxy that
		// discovery contributed — record it so the dashboard can show discovery's unique yield.
		exists, _ := cm.db.ProxyExists(r.job.typ, r.job.addr)
		now := time.Now().UTC().Format("2006-01-02 15:04:05")
		if err := cm.db.StoreProxyTier(r.job.typ, r.job.addr, round2(r.rt), now, r.anon); err != nil {
			log.Printf("discover: store %s %s: %v", r.job.typ, r.job.addr, err)
			continue
		}
		stored++
		if !exists { // wasn't in the pool before → net-new proxy from discovery
			_ = cm.db.RecordDiscovered(r.job.typ, r.job.addr, now)
			if _, seen := newSet[r.job.addr]; !seen {
				newSet[r.job.addr] = struct{}{}
				netNew = append(netNew, r.job.addr)
			}
		}
		if stored%25 == 0 {
			cm.refreshCacheFromDB() // push fresh survivors to the relay mid-stream
		}
	}
	cm.refreshCacheFromDB()
	log.Printf("discover: validated %d candidates, stored %d proxies (%d net-new)", processed, stored, len(netNew))
	return stored, netNew, nil
}

// setHeaders applies the browser-like User-Agent (+ a permissive Accept) that gets requests
// past anti-bot gateways which reject the default Go user-agent.
func setHeaders(req *http.Request) {
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "*/*")
}

// ipResult is a parsed IP-echo response: the origin the target saw (possibly a comma-joined
// X-Forwarded-For chain) and, for header-reflecting endpoints (httpbin /get), the request
// headers the target received — which drive anonymity classification.
type ipResult struct {
	origin     string
	headers    map[string]string
	hasHeaders bool
}

// parseIPResult extracts origin (+ headers, when present) from an IP-echo body: JSON
// ({"origin"/"ip":…, "headers":{…}} httpbin) or a bare plaintext IP (icanhazip/ipify text).
func parseIPResult(body []byte) ipResult {
	t := strings.TrimSpace(string(body))
	if strings.HasPrefix(t, "{") {
		var r struct {
			Origin  string            `json:"origin"`
			IP      string            `json:"ip"`
			Headers map[string]string `json:"headers"`
		}
		if json.Unmarshal([]byte(t), &r) != nil {
			return ipResult{}
		}
		origin := r.Origin
		if origin == "" {
			origin = r.IP
		}
		return ipResult{origin: origin, headers: r.Headers, hasHeaders: r.Headers != nil}
	}
	return ipResult{origin: t}
}

// proxyRevealingHeaders are request headers whose presence (as seen by the target) reveals
// that the connection came through a proxy — the difference between an "anonymous" and an
// "elite" (high-anon) proxy.
var proxyRevealingHeaders = map[string]struct{}{
	"via": {}, "x-forwarded-for": {}, "x-forwarded": {}, "forwarded": {},
	"x-real-ip": {}, "client-ip": {}, "x-client-ip": {}, "x-proxy-id": {},
	"proxy-connection": {}, "x-forwarded-host": {}, "x-forwarded-proto": {},
}

// classifyAnon decides a proxy's anonymity from what the target saw. leaked=true means our
// real IP appeared (origin chain or a header) → transparent → the proxy must be REJECTED.
// Otherwise the tier is "elite" (no proxy-revealing headers) or "anonymous" (some present),
// or "" when the endpoint didn't reflect headers (unknown, but still anonymous by origin).
func classifyAnon(sip string, res ipResult) (tier string, leaked bool) {
	for _, o := range strings.Split(res.origin, ",") {
		if strings.TrimSpace(o) == sip {
			leaked = true
		}
	}
	if !res.hasHeaders {
		return "", leaked
	}
	revealing := false
	for name, val := range res.headers {
		if _, ok := proxyRevealingHeaders[strings.ToLower(strings.TrimSpace(name))]; ok {
			revealing = true
		}
		if strings.Contains(val, sip) {
			leaked = true
		}
	}
	if leaked {
		return "transparent", true
	}
	if revealing {
		return "anonymous", false
	}
	return "elite", false
}

// check validates one proxy by requesting a test URL through it and confirming the returned
// origin is NOT our own IP (i.e. the proxy actually relays + masks). Returns the measured
// response time (seconds) and whether it passed. It tries the test endpoints in order,
// failing over on an endpoint-level error (e.g. 503) but treating a TRANSPORT error as a
// dead proxy (no point trying other endpoints through it). Closes idle connections so a
// full sweep doesn't leak a transport/fd per proxy.
func (cm *CheckManager) check(ctx context.Context, sip string, job proxyJob) (float64, string, bool) {
	if sip == "" {
		return 0, "", false
	}
	timeout := cm.cfg.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	// A short connect timeout fails dead proxies fast (so a sweep converges) while the
	// overall client Timeout still gives a slow-but-alive proxy time to answer.
	connectTimeout := cm.cfg.ConnectTimeout
	if connectTimeout <= 0 || connectTimeout > timeout {
		connectTimeout = timeout
	}
	dialer := &net.Dialer{Timeout: connectTimeout}
	var transport *http.Transport
	if job.typ == "socks4" {
		// net/http can't proxy socks4, so dial the test target THROUGH the socks4 proxy and
		// let the transport run TLS/HTTP over that tunnel (socks4a resolves the hostname).
		addr := job.addr
		transport = &http.Transport{
			DialContext: func(ctx context.Context, _, target string) (net.Conn, error) {
				dctx, cancel := context.WithTimeout(ctx, connectTimeout)
				defer cancel()
				return socks.Dial4(dctx, addr, target)
			},
		}
	} else {
		proxyURL, err := url.Parse(job.typ + "://" + job.addr)
		if err != nil {
			return 0, "", false
		}
		transport = &http.Transport{Proxy: http.ProxyURL(proxyURL), DialContext: dialer.DialContext}
		if job.typ == "https" {
			// An https proxy's own hop is TLS. Free https proxies almost universally present
			// self-signed/mismatched certs, so verifying that hop would reject them ALL (why
			// the https pool was always empty). Skip verification here — matches the relay,
			// which dials https upstreams the same way. (The test URL is a throwaway IP echo.)
			transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		}
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: timeout}

	for _, testURL := range cm.TestURLs {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, testURL, nil)
		if err != nil {
			continue
		}
		setHeaders(req)
		start := time.Now()
		resp, err := client.Do(req)
		if err != nil {
			// Transport error → the PROXY failed (unreachable/refused/timeout), not the
			// endpoint; other endpoints won't fare better through a dead proxy.
			return 0, "", false
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
		rt := time.Since(start).Seconds()
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			continue // endpoint problem (e.g. 503) — try the next test URL through this proxy
		}
		res := parseIPResult(body)
		if res.origin == "" {
			continue
		}
		// Classify anonymity. A leak (our IP in the origin chain OR any reflected header)
		// means transparent → reject; otherwise keep, tagged elite/anonymous (or "" when the
		// endpoint didn't reflect headers).
		tier, leaked := classifyAnon(sip, res)
		if leaked {
			return 0, "", false
		}
		// Honeypot/tamper check: reject proxies that rewrite plaintext HTTP responses.
		if cm.cfg.HoneypotCheck && !honeypotClean(ctx, client, honeypotCanaries) {
			return 0, "", false
		}
		return rt, tier, true
	}
	return 0, "", false
}

// honeypotClean fetches plaintext canaries through the proxy client (in order) and reports
// whether it is untampered. It is FALSE-POSITIVE-SAFE: transport errors / non-200 (the
// endpoint being unreachable through this proxy) fall through to the next canary; only a
// clean 200 whose body fails the canary's check (e.g. HTML where an IP was expected) is
// treated as tampering. If NO canary responds, it returns true (don't penalize).
func honeypotClean(ctx context.Context, client *http.Client, canaries []canary) bool {
	for _, c := range canaries {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
		if err != nil {
			continue
		}
		setHeaders(req)
		resp, err := client.Do(req)
		if err != nil {
			continue // unreachable through this proxy — try the next canary
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			continue
		}
		return c.ok(string(body)) // first responsive canary decides
	}
	return true
}

// refreshCacheFromDB rebuilds the in-memory cache (read by the relay selector and the
// API) from the authoritative DB state after a cycle.
func (cm *CheckManager) refreshCacheFromDB() {
	if cm.db == nil {
		return
	}
	next := make(map[string][]string)
	for _, typ := range testableTypes {
		if list, err := cm.db.GetProxiesByType(typ); err == nil && len(list) > 0 {
			next[typ] = list
		}
	}
	cm.mu.Lock()
	cm.cache = next
	cm.mu.Unlock()
}

func (cm *CheckManager) deleteScanResults(scanIPs []string) {
	if cm.db != nil && len(scanIPs) > 0 {
		_ = cm.db.DeleteScanResults(scanIPs)
	}
}

func round2(f float64) float64 { return float64(int64(f*100+0.5)) / 100 }

// fetchPublicIP returns our own public IP, trying each configured endpoint in order until
// one succeeds (so a single provider outage/503 doesn't stall the whole pipeline).
func (cm *CheckManager) fetchPublicIP(ctx context.Context) (string, error) {
	var lastErr error
	for _, u := range cm.IPURLs {
		ip, err := cm.fetchSelfIP(ctx, u)
		if err != nil {
			lastErr = fmt.Errorf("%s: %w", u, err)
			continue
		}
		return ip, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no self-IP endpoints configured")
	}
	return "", lastErr
}

func (cm *CheckManager) fetchSelfIP(ctx context.Context, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	setHeaders(req)
	resp, err := cm.directClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("bad status: %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return "", err
	}
	// Directly (not through a proxy) the origin is just our IP; take the first component
	// and validate it parses as an IP.
	first := strings.TrimSpace(strings.Split(parseIPResult(body).origin, ",")[0])
	if net.ParseIP(first) == nil {
		return "", fmt.Errorf("unparseable IP %q", first)
	}
	return first, nil
}

func (cm *CheckManager) fetchPublicProxies(ctx context.Context) map[string][]string {
	proxies := make(map[string][]string)
	var mu sync.Mutex
	var wg sync.WaitGroup
	var failed int
	dedupe := &sync.Map{}
	for _, u := range cm.ListURLs {
		wg.Add(1)
		go func(urlStr string) {
			defer wg.Done()
			typ := getProxyType(urlStr)
			list, err := cm.fetchProxyList(ctx, urlStr)
			if err != nil {
				// Don't spam every URL, but surface that a source failed so a fully-blocked
				// egress (every list failing) is visible rather than a silent empty harvest.
				mu.Lock()
				failed++
				mu.Unlock()
				log.Printf("checker: proxy list fetch failed: %s (%v)", urlStr, err)
				return
			}
			for _, p := range list {
				if _, loaded := dedupe.LoadOrStore(p, true); loaded {
					continue
				}
				mu.Lock()
				proxies[typ] = append(proxies[typ], p)
				mu.Unlock()
			}
		}(u)
	}
	wg.Wait()
	return proxies
}

func (cm *CheckManager) fetchProxyList(ctx context.Context, urlStr string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, nil)
	if err != nil {
		return nil, err
	}
	resp, err := cm.directClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxListBytes))
	if err != nil {
		return nil, err
	}
	var proxies []string
	for _, line := range strings.Split(string(body), "\n") {
		if addr, ok := normalizeProxyLine(line); ok {
			proxies = append(proxies, addr)
		}
	}
	return proxies, nil
}

// normalizeProxyLine cleans one line from a public proxy list into a bare "host:port",
// returning ok=false for blanks, comments, and anything not shaped like host:port. It
// tolerates the formats seen across the configured sources: a leading scheme
// ("http://1.2.3.4:80" — proxifly) and trailing columns ("1.2.3.4:80 US",
// "1.2.3.4:80\t1200ms"). It also rejects junk a list may inject (e.g. an upstream's
// "error code: 502"), so a transient source hiccup can't poison the candidate set.
func normalizeProxyLine(line string) (string, bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", false
	}
	// Keep only the first whitespace-delimited token (drop trailing country/latency cols).
	if i := strings.IndexAny(line, " \t"); i >= 0 {
		line = line[:i]
	}
	// Strip a leading scheme:// (http/https/socks4/socks5/...).
	if i := strings.Index(line, "://"); i >= 0 {
		line = line[i+3:]
	}
	host, port, err := net.SplitHostPort(line)
	if err != nil || host == "" {
		return "", false
	}
	if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
		return "", false
	}
	return line, true
}

func getProxyType(u string) string {
	lower := strings.ToLower(u)
	// Strip the URL's own scheme first so the "https://" prefix of EVERY source URL doesn't
	// false-match the https branch — the type is inferred from the path/filename.
	if i := strings.Index(lower, "://"); i >= 0 {
		lower = lower[i+3:]
	}
	switch {
	case strings.Contains(lower, "socks4"):
		return "socks4"
	case strings.Contains(lower, "socks5"):
		return "socks5"
	case strings.Contains(lower, "https"):
		return "https"
	default:
		return "http"
	}
}

// Cache returns a copy of the current in-memory proxy cache grouped by type.
func (cm *CheckManager) Cache() map[string][]string {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	copyCache := make(map[string][]string, len(cm.cache))
	for k, v := range cm.cache {
		copyCache[k] = append([]string(nil), v...)
	}
	return copyCache
}
