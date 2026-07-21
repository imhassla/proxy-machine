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

// DiscoverNeighbors derives neighbor candidates from the proxies already in the DB and
// port-scans them through the validated pool (anonymously, via socks5/socks4/http egress),
// writing open ip:ports to _scan_results for the checker to validate as every type. Returns
// the number of open neighbor ip:ports queued. A no-op (0, nil) when the pool isn't dense
// enough yet. Safe to call repeatedly — already-known and dead neighbors are simply re-probed.
func (s *Scanner) DiscoverNeighbors(ctx context.Context, o DiscoverOptions) (int, error) {
	var known []string
	for _, typ := range []string{"http", "https", "socks4", "socks5"} {
		ps, err := s.db.GetProxiesByType(typ)
		if err != nil {
			return 0, fmt.Errorf("load %s proxies: %w", typ, err)
		}
		known = append(known, ps...)
	}
	cidrs, ports := deriveNeighborhoods(known, o.MinDensity, o.MinPortHits, o.MaxPorts)
	if len(cidrs) == 0 || len(ports) == 0 {
		log.Printf("discover: no dense neighborhoods yet (known=%d, minDensity=%d) — skipping this pass", len(known), o.MinDensity)
		return 0, nil
	}
	log.Printf("discover: scanning %d neighbor /24s x %d ports (derived from %d known proxies) through the pool", len(cidrs), len(ports), len(known))
	n, err := s.scan(ctx, &Options{
		CIDRs:    cidrs,
		Ports:    ports,
		Workers:  o.Workers,
		Timeout:  o.Timeout,
		MaxHosts: o.MaxHosts,
	})
	if err != nil {
		return n, err
	}
	log.Printf("discover: found %d open neighbor ip:ports → queued to _scan_results for validation", n)
	return n, nil
}
