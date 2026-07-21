package scanner

import (
	"context"
	"fmt"
	"log"
	"math/rand"
	"net"
	"sort"
	"strconv"
	"time"
)

// commonProxyPorts are the ports proxies most commonly run on — used by port-expansion to test
// OTHER ports on a host already known to run a proxy (public lists usually list only one).
var commonProxyPorts = []int{80, 8080, 3128, 8000, 8888, 1080, 8081, 8118, 3129, 8443, 1081, 1082, 9002, 4145, 8090}

// sequentialCandidates expands each "ip:port" into its sequential-IP neighbors on the SAME
// port (ip ± 1..span) — providers allocate contiguous IP blocks all running the same proxy, so
// public lists that captured a few of them leave the rest to be found here. IPv4 only.
func sequentialCandidates(pairs []string, span int) []string {
	var out []string
	for _, hp := range pairs {
		host, portStr, err := net.SplitHostPort(hp)
		if err != nil {
			continue
		}
		ip := net.ParseIP(host).To4()
		if ip == nil {
			continue
		}
		for d := -span; d <= span; d++ {
			if d == 0 {
				continue
			}
			n := int(ip[3]) + d
			if n < 0 || n > 255 {
				continue
			}
			out = append(out, fmt.Sprintf("%d.%d.%d.%d:%s", ip[0], ip[1], ip[2], n, portStr))
		}
	}
	return out
}

// portExpansionCandidates emits host:port for every common proxy port on each known host.
func portExpansionCandidates(hosts []string, ports []int) []string {
	out := make([]string, 0, len(hosts)*len(ports))
	for _, h := range hosts {
		for _, p := range ports {
			out = append(out, h+":"+strconv.Itoa(p))
		}
	}
	return out
}

// portWindowCandidates expands each "ip:port" into neighboring PORTS on the SAME host
// (port ± 1..window) — a host running a proxy on one port often runs more on adjacent ports
// (providers cluster proxy ports), which common-port expansion misses.
func portWindowCandidates(pairs []string, window int) []string {
	var out []string
	for _, hp := range pairs {
		host, portStr, err := net.SplitHostPort(hp)
		if err != nil {
			continue
		}
		port, err := strconv.Atoi(portStr)
		if err != nil {
			continue
		}
		for d := -window; d <= window; d++ {
			if d == 0 {
				continue
			}
			p := port + d
			if p < 1 || p > 65535 {
				continue
			}
			out = append(out, host+":"+strconv.Itoa(p))
		}
	}
	return out
}

// AdaptiveCandidates returns a WIDE expansion around a single freshly-confirmed proxy — many
// neighboring ports on the same host plus the same port on many neighboring IPs — so once one
// member of a proxy block is found, discovery grabs the rest of the block (contiguous port
// ranges / IP ranges the provider allocated). Used by the adaptive rounds after each pass.
func AdaptiveCandidates(ipPort string, portWindow, seqSpan int) []string {
	one := []string{ipPort}
	out := portWindowCandidates(one, portWindow)
	return append(out, sequentialCandidates(one, seqSpan)...)
}

// ExpansionCandidates builds validate-only discovery candidates from a (shuffled) sample of the
// known pool: sequential-IP neighbors + common-port expansion, deduped. These need no port
// scan — the caller validates each directly — and in testing yielded net-new proxies at
// hundreds of times the rate of the /24 neighbor scan. sample<=0 uses the whole pool.
func (s *Scanner) ExpansionCandidates(sample, seqSpan, portWindow int) ([]string, error) {
	var pairs []string
	seenPair := map[string]struct{}{}
	for _, typ := range []string{"http", "https", "socks4", "socks5"} {
		ps, err := s.db.GetProxiesByType(typ)
		if err != nil {
			return nil, fmt.Errorf("load %s proxies: %w", typ, err)
		}
		for _, p := range ps {
			if _, ok := seenPair[p]; !ok {
				seenPair[p] = struct{}{}
				pairs = append(pairs, p)
			}
		}
	}
	if sample > 0 && len(pairs) > sample {
		rand.Shuffle(len(pairs), func(i, j int) { pairs[i], pairs[j] = pairs[j], pairs[i] })
		pairs = pairs[:sample]
	}
	hostSet := map[string]struct{}{}
	var hosts []string
	for _, hp := range pairs {
		if h, _, err := net.SplitHostPort(hp); err == nil {
			if _, ok := hostSet[h]; !ok {
				hostSet[h] = struct{}{}
				hosts = append(hosts, h)
			}
		}
	}
	set := map[string]struct{}{}
	var out []string
	add := func(c string) {
		if _, ok := set[c]; !ok {
			set[c] = struct{}{}
			out = append(out, c)
		}
	}
	for _, c := range sequentialCandidates(pairs, seqSpan) {
		add(c)
	}
	for _, c := range portWindowCandidates(pairs, portWindow) {
		add(c)
	}
	for _, c := range portExpansionCandidates(hosts, commonProxyPorts) {
		add(c)
	}
	return out, nil
}

// DiscoverOptions tunes neighbor discovery — deriving new scan targets from the proxies
// already in the DB, then port-scanning them through the validated pool.
type DiscoverOptions struct {
	MinDensity  int           // min distinct known proxies in a /24 for it to be a candidate block
	MinPortHits int           // min times a port recurs across candidate /24s to be scanned
	MaxPorts    int           // cap on distinct ports scanned (top-N by recurrence; 0 = no cap)
	Workers     int           // scan worker pool size
	Timeout     time.Duration // per-probe timeout
	MaxHosts    int           // cap on expanded host IPs (guards OOM)
}

// deriveNeighborhoods is the pure, testable core of neighbor discovery. It groups the known
// "ip:port" proxies by /24 and returns (a) the CIDRs of every /24 that hosts at least
// minDensity distinct proxies — the provider blocks where a neighbor is most likely to also be
// a proxy — and (b) the ports that recur across those blocks (>= minPortHits, top maxPorts by
// recurrence). Single-occurrence ports (the long random tail) are dropped as noise.
func deriveNeighborhoods(known []string, minDensity, minPortHits, maxPorts int) (cidrs []string, ports []int) {
	if minDensity < 1 {
		minDensity = 1
	}
	if minPortHits < 1 {
		minPortHits = 1
	}
	// /24 → set of distinct ip:port (so density counts distinct proxies, not duplicates).
	perNet := map[string]map[string]struct{}{}
	for _, hp := range known {
		net24, ok := slash24(hp)
		if !ok {
			continue
		}
		if perNet[net24] == nil {
			perNet[net24] = map[string]struct{}{}
		}
		perNet[net24][hp] = struct{}{}
	}
	dense := map[string]bool{}
	for net24, set := range perNet {
		if len(set) >= minDensity {
			dense[net24] = true
		}
	}
	if len(dense) == 0 {
		return nil, nil
	}
	// Port recurrence across the dense blocks only.
	portHits := map[int]int{}
	for _, hp := range known {
		net24, ok := slash24(hp)
		if !ok || !dense[net24] {
			continue
		}
		_, ps, err := net.SplitHostPort(hp)
		if err != nil {
			continue
		}
		if port, err := strconv.Atoi(ps); err == nil {
			portHits[port]++
		}
	}
	type pc struct{ port, hits int }
	var pcs []pc
	for port, hits := range portHits {
		if hits >= minPortHits {
			pcs = append(pcs, pc{port, hits})
		}
	}
	// Most-recurring first; ties by port for determinism.
	sort.Slice(pcs, func(i, j int) bool {
		if pcs[i].hits != pcs[j].hits {
			return pcs[i].hits > pcs[j].hits
		}
		return pcs[i].port < pcs[j].port
	})
	if maxPorts > 0 && len(pcs) > maxPorts {
		pcs = pcs[:maxPorts]
	}
	for _, x := range pcs {
		ports = append(ports, x.port)
	}
	sort.Ints(ports)
	for net24 := range dense {
		cidrs = append(cidrs, net24+".0/24")
	}
	sort.Strings(cidrs)
	return cidrs, ports
}

// slash24 returns the "a.b.c" /24 prefix of an "ip:port" proxy (IPv4 only).
func slash24(hostPort string) (string, bool) {
	host, _, err := net.SplitHostPort(hostPort)
	if err != nil {
		return "", false
	}
	ip := net.ParseIP(host).To4()
	if ip == nil {
		return "", false
	}
	return fmt.Sprintf("%d.%d.%d", ip[0], ip[1], ip[2]), true
}

// neighborhoodTargets loads the known proxies and derives the (cidrs, ports) to scan. Returns
// ok=false (after logging) when the pool isn't dense enough yet.
func (s *Scanner) neighborhoodTargets(o DiscoverOptions) (cidrs []string, ports []int, ok bool, err error) {
	var known []string
	for _, typ := range []string{"http", "https", "socks4", "socks5"} {
		ps, e := s.db.GetProxiesByType(typ)
		if e != nil {
			return nil, nil, false, fmt.Errorf("load %s proxies: %w", typ, e)
		}
		known = append(known, ps...)
	}
	cidrs, ports = deriveNeighborhoods(known, o.MinDensity, o.MinPortHits, o.MaxPorts)
	if len(cidrs) == 0 || len(ports) == 0 {
		log.Printf("discover: no dense neighborhoods yet (known=%d, minDensity=%d) — skipping this pass", len(known), o.MinDensity)
		return nil, nil, false, nil
	}
	log.Printf("discover: scanning %d neighbor /24s x %d ports (derived from %d known proxies) through the pool", len(cidrs), len(ports), len(known))
	return cidrs, ports, true, nil
}

// DiscoverNeighbors derives neighbor candidates from the proxies already in the DB and
// port-scans them through the validated pool (anonymously, via socks5/socks4/http egress),
// writing open ip:ports to _scan_results for the checker to validate as every type. Returns
// the number of open neighbor ip:ports queued. A no-op (0, nil) when the pool isn't dense
// enough yet. Prefer DiscoverNeighborsStream for immediate, continuous validation.
func (s *Scanner) DiscoverNeighbors(ctx context.Context, o DiscoverOptions) (int, error) {
	cidrs, ports, ok, err := s.neighborhoodTargets(o)
	if err != nil || !ok {
		return 0, err
	}
	n, err := s.scan(ctx, &Options{CIDRs: cidrs, Ports: ports, Workers: o.Workers, Timeout: o.Timeout, MaxHosts: o.MaxHosts, ScreenGrantAll: true})
	if err != nil {
		return n, err
	}
	log.Printf("discover: found %d open neighbor ip:ports → queued to _scan_results for validation", n)
	return n, nil
}

// DiscoverNeighborsStream is like DiscoverNeighbors but invokes onOpen(ipPort) for EACH open
// neighbor AS IT IS FOUND, instead of batching to _scan_results. Wire onOpen into immediate
// validation+storage (e.g. checker.ValidateAndStoreStream) so discovered proxies of every type
// land in the DB continuously, with no wait for a checker cycle. Returns the count of open
// ip:ports found.
func (s *Scanner) DiscoverNeighborsStream(ctx context.Context, o DiscoverOptions, onOpen func(ipPort string)) (int, error) {
	cidrs, ports, ok, err := s.neighborhoodTargets(o)
	if err != nil || !ok {
		return 0, err
	}
	return s.scanEmit(ctx, &Options{CIDRs: cidrs, Ports: ports, Workers: o.Workers, Timeout: o.Timeout, MaxHosts: o.MaxHosts, ScreenGrantAll: true}, onOpen)
}
