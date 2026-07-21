package scanner

import (
	"context"
	"fmt"
	"log"
	"net"
	"sort"
	"strconv"
	"time"
)

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
