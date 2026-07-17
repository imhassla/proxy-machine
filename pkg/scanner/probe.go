package scanner

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// dialFunc opens a TCP connection to addr with the given timeout and context.
type dialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// prober probes target ip:ports through a rotating list of socks4 proxies.
type prober struct {
	proxies []string
	step    uint32
	timeout time.Duration
	dial    dialFunc
}

// newProber creates a prober that uses proxies as socks4 relays.
func newProber(proxies []string, timeout time.Duration, dial dialFunc) *prober {
	if dial == nil {
		dial = defaultDial
	}
	return &prober{
		proxies: proxies,
		timeout: timeout,
		dial:    dial,
	}
}

// defaultDial relies on the context deadline for the connect timeout (set by the prober
// from -timeout) rather than a hardcoded dialer timeout, so -timeout is authoritative.
var defaultDial dialFunc = func(ctx context.Context, network, addr string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, addr)
}

// withTimeout derives a context bounded by the prober's timeout (the -timeout flag), so
// both the proxied and direct probes actually honor it on connect.
func (p *prober) withTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	if p.timeout > 0 {
		return context.WithTimeout(ctx, p.timeout)
	}
	return context.WithCancel(ctx)
}

// nextProxy returns the next proxy in the list in round-robin fashion.
func (p *prober) nextProxy() (string, error) {
	if len(p.proxies) == 0 {
		return "", errors.New("no proxies available")
	}
	idx := int(atomic.AddUint32(&p.step, 1)-1) % len(p.proxies)
	return p.proxies[idx], nil
}

// probe reports whether the target ip:port is open. With socks4 proxies configured it
// connects THROUGH a rotating proxy (anonymous); with none, it falls back to a DIRECT
// TCP connect so a fresh install can bootstrap (no proxies to harvest through yet).
func (p *prober) probe(ctx context.Context, j job) (bool, error) {
	if len(p.proxies) == 0 {
		return p.probeDirect(ctx, j)
	}
	ctx, cancel := p.withTimeout(ctx)
	defer cancel()
	proxy, err := p.nextProxy()
	if err != nil {
		return false, err
	}

	proxyHost, proxyPort, err := net.SplitHostPort(proxy)
	if err != nil {
		return false, fmt.Errorf("invalid proxy address %q: %w", proxy, err)
	}

	proxyPortNum, err := strconv.Atoi(proxyPort)
	if err != nil {
		return false, fmt.Errorf("invalid proxy port %q: %w", proxyPort, err)
	}

	addr := net.JoinHostPort(proxyHost, strconv.Itoa(proxyPortNum))
	conn, err := p.dial(ctx, "tcp", addr)
	if err != nil {
		return false, nil // proxy unreachable, treat as closed result.
	}
	defer conn.Close()

	if p.timeout > 0 {
		if err := conn.SetDeadline(time.Now().Add(p.timeout)); err != nil {
			return false, err
		}
	}

	targetIP := net.ParseIP(j.ip)
	if targetIP == nil {
		return false, fmt.Errorf("invalid target IP %q", j.ip)
	}
	targetIP = targetIP.To4()
	if targetIP == nil {
		return false, fmt.Errorf("target IP %q is not IPv4", j.ip)
	}

	req := buildSocks4Request(uint16(j.port), targetIP)
	if _, err := conn.Write(req); err != nil {
		return false, nil
	}

	// A SOCKS4 reply is exactly 8 bytes; ReadFull avoids a short read being misjudged as
	// closed (a single Read can return <8 bytes, leaving resp[1]=0 = "rejected").
	resp := make([]byte, 8)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return false, nil
	}
	// VN (reply version) must be 0x00 and CD (status) 0x5a (request granted).
	return resp[0] == 0x00 && resp[1] == 0x5a, nil
}

// probeDirect reports whether the target ip:port accepts a TCP connection (open),
// from our own address. A dial error (refused/timeout/filtered) is a closed result,
// not an error — that is the correct semantics for a port scan from this vantage.
func (p *prober) probeDirect(ctx context.Context, j job) (bool, error) {
	ctx, cancel := p.withTimeout(ctx)
	defer cancel()
	addr := net.JoinHostPort(j.ip, strconv.Itoa(j.port))
	conn, err := p.dial(ctx, "tcp", addr)
	if err != nil {
		return false, nil
	}
	_ = conn.Close()
	return true, nil
}

// buildSocks4Request builds a SOCKS4 CONNECT request.
func buildSocks4Request(port uint16, ip net.IP) []byte {
	ip = ip.To4()
	req := make([]byte, 0, 9)
	req = append(req, 0x04, 0x01)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, port)
	req = append(req, portBytes...)
	req = append(req, ip...)
	req = append(req, 0x00) // empty userid
	return req
}

func splitPorts(s string) ([]int, error) {
	var ports []int
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		p, err := strconv.Atoi(part)
		if err != nil {
			return nil, fmt.Errorf("invalid port %q: %w", part, err)
		}
		if p < 1 || p > 65535 {
			return nil, fmt.Errorf("port %d out of range", p)
		}
		ports = append(ports, p)
	}
	return ports, nil
}
