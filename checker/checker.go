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
	proxyTestURLs = []string{
		"https://api.ipify.org",
		"https://checkip.amazonaws.com",
		"https://httpbin.org/ip",
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
		"https://raw.githubusercontent.com/mmpx12/proxy-list/master/http.txt",
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
		"https://raw.githubusercontent.com/mmpx12/proxy-list/master/socks5.txt",
		// socks4
		"https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt",
		"https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks4.txt",
		"https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/socks4/data.txt",
		"https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks4.txt",
		"https://raw.githubusercontent.com/mmpx12/proxy-list/master/socks4.txt",
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
	job proxyJob
	rt  float64
	ok  bool
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

	// Endpoints used for validation, each a failover list tried in order. Default to the
	// public IP-echo / proxy-list URLs; overridable (e.g. self-hosted echoes, or to point
	// tests at local fakes).
	IPURLs   []string // self-IP echoes (fetched directly)
	TestURLs []string // proxy-test targets (fetched THROUGH each candidate)
	ListURLs []string // public proxy-list sources
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
			if cm.db != nil {
				// last_checked at the moment of storing (not cycle start): in a long cycle
				// a cycle-start timestamp would already be stale and get filtered by the
				// API's default age window.
				now := time.Now().UTC().Format("2006-01-02 15:04:05")
				if err := cm.db.StoreProxy(r.job.typ, r.job.addr, round2(r.rt), now); err != nil {
					log.Printf("checker: store %s %s: %v", r.job.typ, r.job.addr, err)
				}
			}
			// Push newly-stored proxies into the relay cache and log progress periodically.
			if okCount%25 == 0 {
				cm.refreshCacheFromDB()
				log.Printf("checker: progress — %d valid so far (%d/%d checked)", okCount, processed, len(jobs))
			}
		} else if r.job.recheck && cm.db != nil {
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
	// The scanner's candidates have now been classified/validated, so consume them
	// (mirrors checker.py -scan clearing _scan_results) regardless of outcome.
	cm.deleteScanResults(scanIPs)

	cm.refreshCacheFromDB()
	log.Printf("checker: cycle done in %s: %d/%d validated OK (http=%d https=%d socks4=%d socks5=%d), %d pruned dead",
		time.Since(start).Round(time.Second), okCount, len(jobs),
		stored["http"], stored["https"], stored["socks4"], stored["socks5"], prunedCount)
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
		// get a fresh last_checked.
		for _, typ := range testableTypes {
			stored, _ := cm.db.GetProxiesByType(typ)
			for _, p := range stored {
				add(p, typ, true)
			}
		}
	}
	return jobs, scanIPs
}

// validateStream runs jobs through a bounded worker pool and STREAMS each result on the
// returned channel as it's checked (rather than collecting the whole batch first), so the
// caller can persist survivors in real time — with 100k+ candidates a batch-at-the-end
// approach leaves the DB empty for the entire (very long) cycle. The channel closes when
// every job has been checked (or ctx is cancelled).
func (cm *CheckManager) validateStream(ctx context.Context, sip string, jobs []proxyJob) <-chan checkResult {
	workers := cm.cfg.Workers
	if workers <= 0 {
		workers = 1
	}
	if workers > len(jobs) {
		workers = len(jobs)
	}
	in := make(chan proxyJob)
	out := make(chan checkResult, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range in {
				rt, ok := cm.check(ctx, sip, job)
				select {
				case out <- checkResult{job: job, rt: rt, ok: ok}:
				case <-ctx.Done():
					return
				}
			}
		}()
	}
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
	go func() {
		wg.Wait()
		close(out)
	}()
	return out
}

// setHeaders applies the browser-like User-Agent (+ a permissive Accept) that gets requests
// past anti-bot gateways which reject the default Go user-agent.
func setHeaders(req *http.Request) {
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "*/*")
}

// parseOrigin extracts the echoed origin from an IP-echo response body: JSON
// ({"origin":…} httpbin, or {"ip":…} ipify/myip) or a bare plaintext IP (icanhazip,
// ifconfig.me, ipify text). httpbin's origin may be a comma-joined X-Forwarded-For chain.
func parseOrigin(body []byte) string {
	t := strings.TrimSpace(string(body))
	if strings.HasPrefix(t, "{") {
		var r struct {
			Origin string `json:"origin"`
			IP     string `json:"ip"`
		}
		if json.Unmarshal([]byte(t), &r) == nil {
			if r.Origin != "" {
				return r.Origin
			}
			return r.IP
		}
		return ""
	}
	return t
}

// check validates one proxy by requesting a test URL through it and confirming the returned
// origin is NOT our own IP (i.e. the proxy actually relays + masks). Returns the measured
// response time (seconds) and whether it passed. It tries the test endpoints in order,
// failing over on an endpoint-level error (e.g. 503) but treating a TRANSPORT error as a
// dead proxy (no point trying other endpoints through it). Closes idle connections so a
// full sweep doesn't leak a transport/fd per proxy.
func (cm *CheckManager) check(ctx context.Context, sip string, job proxyJob) (float64, bool) {
	if sip == "" {
		return 0, false
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
			return 0, false
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
			return 0, false
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
		rt := time.Since(start).Seconds()
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			continue // endpoint problem (e.g. 503) — try the next test URL through this proxy
		}
		origin := parseOrigin(body)
		if origin == "" {
			continue
		}
		// Reject if ANY origin component is our own IP (a transparent proxy leaking the
		// client IP via X-Forwarded-For shows up as a "<self>, <proxy>" chain on httpbin).
		for _, o := range strings.Split(origin, ",") {
			if strings.TrimSpace(o) == sip {
				return 0, false
			}
		}
		return rt, true
	}
	return 0, false
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
	first := strings.TrimSpace(strings.Split(parseOrigin(body), ",")[0])
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
