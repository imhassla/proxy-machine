package scanner

import (
	"fmt"
	"net"
	"strings"
)

// defaultMaxHosts caps how many host IPs one scan will expand, so a wide CIDR (e.g.
// /8 or /0) cannot OOM the process or run unbounded.
const defaultMaxHosts = 1 << 20 // 1,048,576

// validateAndCountHosts parses each CIDR, REJECTS IPv6 (the socks4 + direct IPv4 probe
// path is IPv4-only — a prior bug expanded IPv6 then silently probed nothing), and
// returns the total host count, erroring if it would exceed maxHosts (<=0 →
// defaultMaxHosts). Counting is O(1) per CIDR (from the prefix), so this is a cheap
// pre-flight that surfaces bad-CIDR / IPv6 / too-large errors BEFORE any work starts.
func validateAndCountHosts(cidrs []string, maxHosts int) (int, error) {
	if maxHosts <= 0 {
		maxHosts = defaultMaxHosts
	}
	total := 0
	for _, c := range cidrs {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		_, ipNet, err := net.ParseCIDR(c)
		if err != nil {
			return 0, fmt.Errorf("parse CIDR %q: %w", c, err)
		}
		if ipNet.IP.To4() == nil {
			return 0, fmt.Errorf("CIDR %q is IPv6; only IPv4 is supported", c)
		}
		ones, bits := ipNet.Mask.Size()
		total += 1 << (bits - ones)
		if total > maxHosts {
			return 0, fmt.Errorf("scan would expand to more than %d hosts; narrow the CIDR range(s)", maxHosts)
		}
	}
	return total, nil
}

// streamHostIPs invokes emit for each IPv4 host address across the (pre-validated)
// CIDRs, in order, stopping early if emit returns false. It NEVER materializes the full
// set (O(1) memory) — the fix for the OOM on a large range. Unparseable/IPv6 CIDRs are
// skipped (validateAndCountHosts already rejected them with a clear error).
func streamHostIPs(cidrs []string, emit func(ip string) bool) {
	for _, c := range cidrs {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		_, ipNet, err := net.ParseCIDR(c)
		if err != nil || ipNet.IP.To4() == nil {
			continue
		}
		ip := cloneIP(ipNet.IP.Mask(ipNet.Mask)).To4()
		for ; ipNet.Contains(ip); incrementIP(ip) {
			if !emit(ip.String()) {
				return
			}
		}
	}
}

func cloneIP(ip net.IP) net.IP {
	c := make(net.IP, len(ip))
	copy(c, ip)
	return c
}

// expandCIDR returns all host IP addresses within a CIDR notation.
func expandCIDR(cidr string) ([]string, error) {
	_, ipNet, err := net.ParseCIDR(strings.TrimSpace(cidr))
	if err != nil {
		return nil, fmt.Errorf("parse CIDR %q: %w", cidr, err)
	}

	var ips []string
	for ip := ipNet.IP.Mask(ipNet.Mask); ipNet.Contains(ip); incrementIP(ip) {
		ips = append(ips, ip.String())
	}
	return ips, nil
}

// expandCIDRs expands all provided CIDR strings, deduping and sorting.
func expandCIDRs(cidrs []string) ([]string, error) {
	seen := make(map[string]struct{})
	var all []string
	for _, c := range cidrs {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		ips, err := expandCIDR(c)
		if err != nil {
			return nil, err
		}
		for _, ip := range ips {
			if _, ok := seen[ip]; ok {
				continue
			}
			seen[ip] = struct{}{}
			all = append(all, ip)
		}
	}
	return all, nil
}

func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
