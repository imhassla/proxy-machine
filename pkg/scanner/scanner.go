package scanner

import (
	"context"
	"flag"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"proxymachine/config"
	"proxymachine/db"
)

// proxyDB abstracts the DB operations needed by the scanner.
type proxyDB interface {
	GetProxiesByType(proxyType string) ([]string, error)
	EnsureScanResultsTable() error
	StoreScanResults(ipPorts []string) error
}

// Options holds scanner CLI flags.
type Options struct {
	CIDRs    []string
	Ports    []int
	Workers  int
	Timeout  time.Duration
	DBPath   string
	MaxHosts int // cap on expanded host IPs (<=0 → defaultMaxHosts); guards against OOM
}

// Scanner orchestrates port scanning through socks4 proxies.
type Scanner struct {
	db proxyDB
}

// New returns a Scanner backed by the given proxy DB.
func New(database *db.DB) *Scanner {
	return &Scanner{db: database}
}

func newScannerWithDB(database proxyDB) *Scanner {
	return &Scanner{db: database}
}

// LoadOptions parses command-line flags into scanner options, falling back to
// config defaults for workers, timeout and db path.
func LoadOptions(args []string) (*Options, error) {
	base, err := config.Load([]string{})
	if err != nil {
		return nil, err
	}

	opts := &Options{
		Workers: base.Workers,
		Timeout: base.Timeout,
		DBPath:  base.DBPath,
	}

	var cidr, port string
	var workers int = -1
	var maxHosts int = -1
	var timeout time.Duration = -1
	var dbPath string

	fs := flag.NewFlagSet("scanner", flag.ContinueOnError)
	fs.StringVar(&cidr, "cidr", "", "Comma-separated CIDR ranges to scan")
	fs.StringVar(&port, "port", "", "Comma-separated list of ports to scan")
	fs.IntVar(&workers, "workers", -1, "Number of workers")
	fs.IntVar(&maxHosts, "maxHosts", -1, "Max expanded host IPs (guards OOM; default 1048576)")
	fs.DurationVar(&timeout, "timeout", -1, "Probe timeout")
	fs.StringVar(&dbPath, "dbPath", "", "Path to database file")

	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if maxHosts >= 0 {
		opts.MaxHosts = maxHosts
	}

	if cidr != "" {
		opts.CIDRs = splitTrim(cidr)
	}
	if port != "" {
		parsed, err := splitPorts(port)
		if err != nil {
			return nil, err
		}
		opts.Ports = parsed
	}
	if workers >= 0 {
		opts.Workers = workers
	}
	if timeout >= 0 {
		opts.Timeout = timeout
	}
	if dbPath != "" {
		opts.DBPath = dbPath
	}

	if opts.Workers <= 0 {
		opts.Workers = 4
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 5 * time.Second
	}

	return opts, opts.validate()
}

func (o *Options) validate() error {
	if len(o.CIDRs) == 0 {
		return fmt.Errorf("at least one CIDR range is required")
	}
	if len(o.Ports) == 0 {
		return fmt.Errorf("at least one port is required")
	}
	return nil
}

// Scan expands the provided CIDRs and ports and probes each ip:port through
// alive socks4 proxies stored in the DB. Open ports are written to the
// scan_results table.
func (s *Scanner) Scan(ctx context.Context, opts *Options) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if opts == nil {
		return fmt.Errorf("options are required")
	}
	if err := opts.validate(); err != nil {
		return err
	}

	// socks4 proxies let the scan egress anonymously THROUGH them; when none exist yet
	// (a fresh install — the pipeline can't have harvested any), the prober falls back
	// to DIRECT probing so the scanner can bootstrap instead of dead-locking on an empty
	// table nothing has populated.
	proxies, err := s.db.GetProxiesByType("socks4")
	if err != nil {
		return fmt.Errorf("fetch socks4 proxies: %w", err)
	}

	// Pre-flight: parse + reject IPv6 + bound the host count BEFORE streaming, so a bad
	// or huge range fails fast (and never materializes / OOMs).
	if _, err := validateAndCountHosts(opts.CIDRs, opts.MaxHosts); err != nil {
		return err
	}

	p := newProber(proxies, opts.Timeout, nil)

	jobs := make(chan job)
	go func() {
		defer close(jobs)
		streamHostIPs(opts.CIDRs, func(ip string) bool {
			for _, port := range opts.Ports {
				select {
				case jobs <- job{ip: ip, port: port}:
				case <-ctx.Done():
					return false
				}
			}
			return true
		})
	}()

	results := workerPool(ctx, jobs, opts.Workers, p.probe)

	var open []string
	for r := range results {
		if r.open {
			open = append(open, fmt.Sprintf("%s:%d", r.ip, r.port))
		}
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	if len(open) == 0 {
		return nil
	}

	// Results arrive in nondeterministic order from the concurrent worker pool.
	// Sort by (IP, port) so stored output is deterministic and user-friendly.
	sortIPPorts(open)

	if err := s.db.EnsureScanResultsTable(); err != nil {
		return fmt.Errorf("ensure scan results table: %w", err)
	}
	if err := s.db.StoreScanResults(open); err != nil {
		return fmt.Errorf("store scan results: %w", err)
	}

	return nil
}

// sortIPPorts orders "ip:port" entries by numeric IP then numeric port, so a
// lexical comparison (which would put .10 before .2) doesn't scramble the output.
// Unparseable entries sort after parseable ones, by raw string, so output is
// always total-ordered and deterministic.
func sortIPPorts(ipPorts []string) {
	type key struct {
		ip   net.IP
		port int
		raw  string
		ok   bool
	}
	keys := make([]key, len(ipPorts))
	for i, s := range ipPorts {
		k := key{raw: s}
		if host, portStr, err := net.SplitHostPort(s); err == nil {
			if ip := net.ParseIP(host); ip != nil {
				if port, err := strconv.Atoi(portStr); err == nil {
					k.ip, k.port, k.ok = ip, port, true
				}
			}
		}
		keys[i] = k
	}
	sort.Slice(keys, func(a, b int) bool {
		ka, kb := keys[a], keys[b]
		if ka.ok != kb.ok {
			return ka.ok // parseable entries first
		}
		if !ka.ok {
			return ka.raw < kb.raw
		}
		if c := bytesCompareIP(ka.ip, kb.ip); c != 0 {
			return c < 0
		}
		return ka.port < kb.port
	})
	for i, k := range keys {
		ipPorts[i] = k.raw
	}
}

// bytesCompareIP compares two IPs by their 16-byte representation so v4 and v6
// order consistently.
func bytesCompareIP(a, b net.IP) int {
	a16, b16 := a.To16(), b.To16()
	for i := 0; i < len(a16) && i < len(b16); i++ {
		switch {
		case a16[i] < b16[i]:
			return -1
		case a16[i] > b16[i]:
			return 1
		}
	}
	return len(a16) - len(b16)
}

func splitTrim(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}
