// Package checker manages proxy validation using a bounded worker pool,
// public IP detection, and public proxy list fetching.
package checker

import (
	"context"
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

var (
	publicIPURL  = "https://httpbin.org/ip"
	proxyTestURL = "https://httpbin.org/ip"
	// publicProxyURLs are re-verified public lists (live + substantial + maintained as of
	// 2026-06). Each source's TYPE is inferred from its URL by getProxyType. The checker
	// validates http/socks5/socks4 (see testableTypes). proxifly serves "scheme://ip:port",
	// which normalizeProxyLine strips.
	publicProxyURLs = []string{
		// http (bare ip:port)
		"https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
		"https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-http.txt",
		"https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt",
		// http (scheme://ip:port — normalized)
		"https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/http/data.txt",
		// socks5 (typed via getProxyType on the URL)
		"https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
		"https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks5.txt",
		"https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
		"https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/socks5/data.txt",
		// socks4
		"https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt",
		"https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks4.txt",
		"https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/socks4/data.txt",
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

// CheckManager orchestrates proxy harvesting, validation, persistence and serving.
type CheckManager struct {
	cfg          *config.Config
	db           *db.DB
	cache        map[string][]string
	mu           sync.RWMutex
	directClient *http.Client

	// Endpoints used for validation. Default to the public httpbin/proxy-list URLs;
	// overridable (e.g. a self-hosted IP echo, or to point tests at local fakes).
	IPURL    string   // self-IP echo (fetched directly)
	TestURL  string   // proxy-test target (fetched THROUGH each candidate)
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
		IPURL:        publicIPURL,
		TestURL:      proxyTestURL,
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
	// Re-fetch the self-IP every cycle: without it we cannot tell a working proxy from
	// one that echoes our own IP, so a failed fetch must SKIP the cycle (not validate),
	// and a later cycle recovers — fixing the permanent-degrade-on-startup failure mode.
	sip, err := cm.fetchPublicIP(ctx)
	if err != nil {
		return
	}

	jobs, scanIPs := cm.gatherCandidates(ctx)
	if len(jobs) == 0 {
		cm.deleteScanResults(scanIPs)
		return
	}

	results := cm.validate(ctx, sip, jobs)

	now := time.Now().UTC().Format("2006-01-02 15:04:05")
	var prune = map[string][]string{}
	for _, r := range results {
		if r.ok {
			if cm.db != nil {
				if err := cm.db.StoreProxy(r.job.typ, r.job.addr, round2(r.rt), now); err != nil {
					log.Printf("checker: store %s %s: %v", r.job.typ, r.job.addr, err)
				}
			}
		} else if r.job.recheck && cm.db != nil {
			prune[r.job.typ] = append(prune[r.job.typ], r.job.addr)
		}
	}
	for typ, dead := range prune {
		_ = cm.db.DeleteProxies(typ, dead)
	}
	// The scanner's candidates have now been classified/validated, so consume them
	// (mirrors checker.py -scan clearing _scan_results) regardless of outcome.
	cm.deleteScanResults(scanIPs)

	cm.refreshCacheFromDB()
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

// validate runs jobs through a bounded worker pool, returning a result per job.
func (cm *CheckManager) validate(ctx context.Context, sip string, jobs []proxyJob) []checkResult {
	workers := cm.cfg.Workers
	if workers <= 0 {
		workers = 1
	}
	if workers > len(jobs) {
		workers = len(jobs)
	}
	in := make(chan proxyJob)
	out := make(chan checkResult, len(jobs))
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range in {
				rt, ok := cm.check(ctx, sip, job)
				out <- checkResult{job: job, rt: rt, ok: ok}
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
	wg.Wait()
	close(out)
	var results []checkResult
	for r := range out {
		results = append(results, r)
	}
	return results
}

// check validates one proxy by requesting the test URL through it and confirming the
// returned origin is NOT our own IP (i.e. the proxy actually relays + masks). Returns
// the measured response time (seconds) and whether it passed. It closes its idle
// connections so a full validation sweep doesn't leak a transport/fd per proxy.
func (cm *CheckManager) check(ctx context.Context, sip string, job proxyJob) (float64, bool) {
	if sip == "" {
		return 0, false
	}
	timeout := cm.cfg.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	var transport *http.Transport
	if job.typ == "socks4" {
		// net/http can't proxy socks4, so dial the test target THROUGH the socks4 proxy and
		// let the transport run TLS/HTTP over that tunnel (socks4a resolves the hostname).
		addr := job.addr
		transport = &http.Transport{
			DialContext: func(ctx context.Context, _, target string) (net.Conn, error) {
				return socks.Dial4(ctx, addr, target)
			},
		}
	} else {
		proxyURL, err := url.Parse(job.typ + "://" + job.addr)
		if err != nil {
			return 0, false
		}
		transport = &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: timeout}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cm.TestURL, nil)
	if err != nil {
		return 0, false
	}
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return 0, false
	}
	defer resp.Body.Close()
	rt := time.Since(start).Seconds()
	if resp.StatusCode != http.StatusOK {
		return 0, false
	}
	var result struct {
		Origin string `json:"origin"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&result); err != nil {
		return 0, false
	}
	// httpbin returns the X-Forwarded-For CHAIN as a comma-joined origin
	// ("<self>, <proxy>") for a transparent proxy that leaks the client IP. Comparing
	// the whole string would never equal sip, so such a leaky proxy would pass as
	// anonymous — reject if ANY component is our own IP.
	if result.Origin == "" {
		return 0, false
	}
	for _, o := range strings.Split(result.Origin, ",") {
		if strings.TrimSpace(o) == sip {
			return 0, false
		}
	}
	return rt, true
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

func (cm *CheckManager) fetchPublicIP(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cm.IPURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := cm.directClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("bad status: %d", resp.StatusCode)
	}
	var result struct {
		Origin string `json:"origin"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	if result.Origin == "" {
		return "", fmt.Errorf("empty origin")
	}
	return result.Origin, nil
}

func (cm *CheckManager) fetchPublicProxies(ctx context.Context) map[string][]string {
	proxies := make(map[string][]string)
	var mu sync.Mutex
	var wg sync.WaitGroup
	dedupe := &sync.Map{}
	for _, u := range cm.ListURLs {
		wg.Add(1)
		go func(urlStr string) {
			defer wg.Done()
			typ := getProxyType(urlStr)
			list, err := cm.fetchProxyList(ctx, urlStr)
			if err != nil {
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
	if strings.Contains(lower, "socks4") {
		return "socks4"
	}
	if strings.Contains(lower, "socks5") {
		return "socks5"
	}
	return "http"
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
