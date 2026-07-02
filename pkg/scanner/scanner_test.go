package scanner

import (
	"context"
	"errors"
	"net"
	"reflect"
	"sync/atomic"
	"testing"
	"time"
)

type mockDB struct {
	proxies     []string
	stored      []string
	errGet      error
	errEnsure   error
	errStore    error
	ensureCalls int
}

func (m *mockDB) GetProxiesByType(proxyType string) ([]string, error) {
	return m.proxies, m.errGet
}

func (m *mockDB) EnsureScanResultsTable() error {
	m.ensureCalls++
	return m.errEnsure
}

func (m *mockDB) StoreScanResults(ipPorts []string) error {
	m.stored = append(m.stored, ipPorts...)
	return m.errStore
}

func TestExpandCIDR(t *testing.T) {
	got, err := expandCIDR("127.0.0.0/30")
	if err != nil {
		t.Fatalf("expandCIDR failed: %v", err)
	}
	want := []string{"127.0.0.0", "127.0.0.1", "127.0.0.2", "127.0.0.3"}
	if len(got) != len(want) {
		t.Fatalf("expected %d IPs, got %d", len(want), len(got))
	}
	for i, ip := range want {
		if got[i] != ip {
			t.Errorf("expected IP[%d] = %q, got %q", i, ip, got[i])
		}
	}
}

func TestExpandCIDRsDedupes(t *testing.T) {
	got, err := expandCIDRs([]string{"10.0.0.0/31", "10.0.0.1/32"})
	if err != nil {
		t.Fatalf("expandCIDRs failed: %v", err)
	}
	want := []string{"10.0.0.0", "10.0.0.1"}
	if len(got) != len(want) {
		t.Fatalf("expected %d IPs, got %d", len(want), len(got))
	}
	for i, ip := range want {
		if got[i] != ip {
			t.Errorf("expected IP[%d] = %q, got %q", i, ip, got[i])
		}
	}
}

func TestExpandCIDRInvalid(t *testing.T) {
	_, err := expandCIDR("not-a-cidr")
	if err == nil {
		t.Fatal("expected error for invalid CIDR")
	}
}

func TestSplitPorts(t *testing.T) {
	got, err := splitPorts("80,443,8080")
	if err != nil {
		t.Fatalf("splitPorts failed: %v", err)
	}
	want := []int{80, 443, 8080}
	if len(got) != len(want) {
		t.Fatalf("expected %d ports, got %d", len(want), len(got))
	}
	for i, p := range want {
		if got[i] != p {
			t.Errorf("expected port[%d] = %d, got %d", i, p, got[i])
		}
	}
}

func TestSplitPortsInvalid(t *testing.T) {
	_, err := splitPorts("abc")
	if err == nil {
		t.Fatal("expected error for invalid port")
	}
	_, err = splitPorts("70000")
	if err == nil {
		t.Fatal("expected error for out-of-range port")
	}
}

func TestLoadOptionsDefaults(t *testing.T) {
	opts, err := LoadOptions([]string{
		"-cidr", "192.168.0.0/30",
		"-port", "80,443",
	})
	if err != nil {
		t.Fatalf("LoadOptions failed: %v", err)
	}
	if len(opts.CIDRs) != 1 || opts.CIDRs[0] != "192.168.0.0/30" {
		t.Errorf("unexpected CIDRs: %v", opts.CIDRs)
	}
	if len(opts.Ports) != 2 {
		t.Errorf("expected 2 ports, got %d", len(opts.Ports))
	}
	if opts.Workers != 4 {
		t.Errorf("expected workers 4, got %d", opts.Workers)
	}
}

func TestLoadOptionsMissingCIDR(t *testing.T) {
	_, err := LoadOptions([]string{"-port", "80"})
	if err == nil {
		t.Fatal("expected error when CIDR is missing")
	}
}

func TestLoadOptionsMissingPort(t *testing.T) {
	_, err := LoadOptions([]string{"-cidr", "10.0.0.0/24"})
	if err == nil {
		t.Fatal("expected error when port is missing")
	}
}

func TestWorkerPoolRespectsContext(t *testing.T) {
	jobs := make(chan job, 1)
	jobs <- job{ip: "127.0.0.1", port: 80}
	close(jobs)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	started := make(chan struct{})
	work := func(context.Context, job) (bool, error) {
		close(started)
		return true, nil
	}

	results := workerPool(ctx, jobs, 1, work)
	count := 0
	for range results {
		count++
	}
	if count != 0 {
		t.Fatalf("expected no results after cancel, got %d", count)
	}
}

func TestWorkerPoolBounded(t *testing.T) {
	jobs := make(chan job, 10)
	for i := 0; i < 10; i++ {
		jobs <- job{ip: "127.0.0.1", port: 80 + i}
	}
	close(jobs)

	// running/maxSeen are touched by all worker goroutines concurrently, so they
	// must be atomic — otherwise the observer itself races (and -race fails).
	var running, maxSeen atomic.Int32
	work := func(ctx context.Context, j job) (bool, error) {
		cur := running.Add(1)
		for { // raise maxSeen to at least cur
			m := maxSeen.Load()
			if cur <= m || maxSeen.CompareAndSwap(m, cur) {
				break
			}
		}
		time.Sleep(time.Millisecond)
		running.Add(-1)
		return true, nil
	}

	results := workerPool(context.Background(), jobs, 2, work)
	for range results {
	}
	if got := maxSeen.Load(); got > 2 {
		t.Fatalf("expected at most 2 concurrent workers, saw %d", got)
	}
}

func TestProbeReportsOpen(t *testing.T) {
	p := newProber([]string{"127.0.0.1:1080"}, time.Second, func(ctx context.Context, network, addr string) (net.Conn, error) {
		return &fakeConn{}, nil
	})
	open, err := p.probe(context.Background(), job{ip: "1.2.3.4", port: 80})
	if err != nil {
		t.Fatalf("probe failed: %v", err)
	}
	if !open {
		t.Fatal("expected open result")
	}
}

func TestProbeReportsClosed(t *testing.T) {
	p := newProber([]string{"127.0.0.1:1080"}, time.Second, func(ctx context.Context, network, addr string) (net.Conn, error) {
		return &fakeConn{failHandshake: true}, nil
	})
	open, err := p.probe(context.Background(), job{ip: "1.2.3.4", port: 80})
	if err != nil {
		t.Fatalf("probe failed: %v", err)
	}
	if open {
		t.Fatal("expected closed result")
	}
}

// With no socks4 proxies the prober falls back to a DIRECT TCP probe (bootstrap):
// a successful dial is open; a failed dial is closed (not an error).
func TestProbeDirectNoProxies(t *testing.T) {
	open, err := newProber(nil, time.Second, func(ctx context.Context, network, addr string) (net.Conn, error) {
		return &fakeConn{}, nil
	}).probe(context.Background(), job{ip: "1.2.3.4", port: 80})
	if err != nil || !open {
		t.Fatalf("direct dial success → open: got open=%v err=%v", open, err)
	}

	open, err = newProber(nil, time.Second, func(ctx context.Context, network, addr string) (net.Conn, error) {
		return nil, errors.New("connection refused")
	}).probe(context.Background(), job{ip: "1.2.3.4", port: 80})
	if err != nil || open {
		t.Fatalf("direct dial failure → closed/no-error: got open=%v err=%v", open, err)
	}
}

func TestValidateAndCountHosts(t *testing.T) {
	if _, err := validateAndCountHosts([]string{"2001:db8::/120"}, 0); err == nil {
		t.Error("IPv6 CIDR must be rejected")
	}
	if _, err := validateAndCountHosts([]string{"10.0.0.0/8"}, 1000); err == nil {
		t.Error("over-cap CIDR must error (no OOM)")
	}
	if n, err := validateAndCountHosts([]string{"192.0.2.0/30"}, 0); err != nil || n != 4 {
		t.Errorf("/30 count = %d err = %v, want 4/nil", n, err)
	}
	if _, err := validateAndCountHosts([]string{"not-a-cidr"}, 0); err == nil {
		t.Error("bad CIDR must error")
	}
}

func TestStreamHostIPs(t *testing.T) {
	var got []string
	streamHostIPs([]string{"192.0.2.0/30"}, func(ip string) bool { got = append(got, ip); return true })
	want := []string{"192.0.2.0", "192.0.2.1", "192.0.2.2", "192.0.2.3"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("streamHostIPs = %v, want %v", got, want)
	}
	count := 0
	streamHostIPs([]string{"192.0.2.0/24"}, func(string) bool { count++; return count < 2 })
	if count != 2 {
		t.Errorf("early-stop emitted %d, want 2", count)
	}
}

func TestScanStoresOpenResults(t *testing.T) {
	mock := &mockDB{proxies: []string{"127.0.0.1:1080"}}
	s := newScannerWithDB(mock)

	original := defaultDial
	defaultDial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return &fakeConn{}, nil
	}
	defer func() { defaultDial = original }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	opts := &Options{
		CIDRs:   []string{"192.0.2.0/30"},
		Ports:   []int{80},
		Workers: 2,
		Timeout: time.Second,
	}
	if err := s.Scan(ctx, opts); err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	// /30 = .0–.3, all open on :80. Concurrent workers emit in arbitrary order, but
	// Scan sorts before storing, so the full result is deterministic.
	want := []string{"192.0.2.0:80", "192.0.2.1:80", "192.0.2.2:80", "192.0.2.3:80"}
	if !reflect.DeepEqual(mock.stored, want) {
		t.Errorf("stored results = %v, want %v", mock.stored, want)
	}
	if mock.ensureCalls != 1 {
		t.Errorf("expected EnsureScanResultsTable called once, got %d", mock.ensureCalls)
	}
}

func TestSortIPPorts(t *testing.T) {
	// Numeric order, not lexical: .10 must sort AFTER .2, and ports order numerically.
	in := []string{
		"192.0.2.10:80", "192.0.2.2:80", "192.0.2.2:22", "192.0.2.1:443",
		"not-an-addr", "10.0.0.1:80",
	}
	sortIPPorts(in)
	want := []string{
		"10.0.0.1:80", "192.0.2.1:443", "192.0.2.2:22", "192.0.2.2:80",
		"192.0.2.10:80", "not-an-addr", // unparseable sorts last
	}
	if !reflect.DeepEqual(in, want) {
		t.Errorf("sortIPPorts =\n  %v\nwant\n  %v", in, want)
	}
}

func TestScanCancels(t *testing.T) {
	mock := &mockDB{proxies: []string{"127.0.0.1:1080"}}
	s := newScannerWithDB(mock)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	original := defaultDial
	defaultDial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		time.Sleep(time.Second)
		return &fakeConn{}, nil
	}
	defer func() { defaultDial = original }()

	opts := &Options{
		CIDRs:   []string{"192.0.2.0/24"},
		Ports:   []int{80},
		Workers: 2,
		Timeout: time.Second,
	}
	err := s.Scan(ctx, opts)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

// No socks4 proxies → DIRECT scan (bootstrap), not a deadlock error. Open ports are
// still discovered and stored.
func TestScanNoProxiesDirect(t *testing.T) {
	mock := &mockDB{proxies: []string{}}
	s := newScannerWithDB(mock)

	original := defaultDial
	defaultDial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return &fakeConn{}, nil
	}
	defer func() { defaultDial = original }()

	opts := &Options{CIDRs: []string{"192.0.2.0/30"}, Ports: []int{80}, Workers: 2, Timeout: time.Second}
	if err := s.Scan(context.Background(), opts); err != nil {
		t.Fatalf("direct scan should succeed without proxies, got %v", err)
	}
	want := []string{"192.0.2.0:80", "192.0.2.1:80", "192.0.2.2:80", "192.0.2.3:80"}
	if !reflect.DeepEqual(mock.stored, want) {
		t.Errorf("direct scan stored = %v, want %v", mock.stored, want)
	}
}

// An IPv6 CIDR is rejected up front (the probe path is IPv4-only).
func TestScanRejectsIPv6(t *testing.T) {
	mock := &mockDB{proxies: []string{"127.0.0.1:1080"}}
	s := newScannerWithDB(mock)
	opts := &Options{CIDRs: []string{"2001:db8::/120"}, Ports: []int{80}, Workers: 2, Timeout: time.Second}
	if err := s.Scan(context.Background(), opts); err == nil {
		t.Fatal("expected IPv6 CIDR to be rejected")
	}
}

func TestScanDBGetError(t *testing.T) {
	mock := &mockDB{errGet: errors.New("db down")}
	s := newScannerWithDB(mock)
	opts := &Options{
		CIDRs:   []string{"192.0.2.0/30"},
		Ports:   []int{80},
		Workers: 2,
		Timeout: time.Second,
	}
	err := s.Scan(context.Background(), opts)
	if err == nil {
		t.Fatal("expected error from db")
	}
}

// fakeConn implements net.Conn for unit tests.
type fakeConn struct {
	current       int
	failHandshake bool
	shortReply    bool // deliver a truncated (2-byte) SOCKS4 reply then EOF
}

func (f *fakeConn) Read(b []byte) (int, error) {
	if f.failHandshake {
		return 0, errors.New("handshake failed")
	}
	if f.current == 0 {
		f.current++
		if f.shortReply {
			// Only 2 bytes (a "granted" prefix) then the connection ends — a partial
			// read that a single conn.Read would misjudge but io.ReadFull rejects.
			if len(b) >= 2 {
				b[0], b[1] = 0x00, 0x5a
			}
			return 2, nil
		}
		if len(b) < 8 {
			return 0, errors.New("short buffer")
		}
		b[0] = 0x00
		b[1] = 0x5a // success
		copy(b[2:], []byte{0, 0, 0, 0, 0, 0})
		return 8, nil
	}
	return 0, errors.New("EOF")
}

// A truncated SOCKS4 reply (fewer than 8 bytes) must be judged CLOSED, not falsely open:
// io.ReadFull rejects the short read that a single conn.Read would have accepted.
func TestProbeShortSocks4ReplyIsClosed(t *testing.T) {
	p := newProber([]string{"127.0.0.1:1080"}, time.Second, func(ctx context.Context, network, addr string) (net.Conn, error) {
		return &fakeConn{shortReply: true}, nil
	})
	open, err := p.probe(context.Background(), job{ip: "1.2.3.4", port: 80})
	if err != nil {
		t.Fatalf("probe err: %v", err)
	}
	if open {
		t.Fatal("a truncated SOCKS4 reply must be treated as closed, not open")
	}
}

func (f *fakeConn) Write(b []byte) (int, error) {
	if f.failHandshake && len(b) > 0 {
		return len(b), nil
	}
	return len(b), nil
}

func (f *fakeConn) Close() error                       { return nil }
func (f *fakeConn) LocalAddr() net.Addr                { return nil }
func (f *fakeConn) RemoteAddr() net.Addr               { return nil }
func (f *fakeConn) SetDeadline(t time.Time) error      { return nil }
func (f *fakeConn) SetReadDeadline(t time.Time) error  { return nil }
func (f *fakeConn) SetWriteDeadline(t time.Time) error { return nil }
