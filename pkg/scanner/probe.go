package scanner

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"proxymachine/pkg/socks"
)

// dialFunc opens a TCP connection to addr with the given timeout and context.
type dialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// scanProxy is an egress proxy the scanner tunnels port probes through, tagged with its
// protocol so probe() speaks the right handshake.
type scanProxy struct {
	addr string
	typ  string // "socks5" | "socks4" | "http"
}

// prober probes target ip:ports through a rotating list of egress proxies (socks5/socks4/http).
type prober struct {
	proxies []scanProxy
	step    uint32
	timeout time.Duration
	dial    dialFunc
}

// newProber creates a prober that egresses through the given proxies (any mix of
// socks5/socks4/http). An empty list makes probe() fall back to a DIRECT connect.
func newProber(proxies []scanProxy, timeout time.Duration, dial dialFunc) *prober {
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
func (p *prober) nextProxy() (scanProxy, error) {
	if len(p.proxies) == 0 {
		return scanProxy{}, errors.New("no proxies available")
	}
	idx := int(atomic.AddUint32(&p.step, 1)-1) % len(p.proxies)
	return p.proxies[idx], nil
}

// probe reports whether the target ip:port is open. With egress proxies configured it connects
// THROUGH a rotating proxy (anonymous), speaking that proxy's protocol — SOCKS5, SOCKS4, or
// HTTP CONNECT; with none it falls back to a DIRECT TCP connect so a fresh install can
// bootstrap (no proxies to harvest through yet). A dead/blocking proxy is a closed result, not
// an error (same semantics as an unreachable target from that vantage).
func (p *prober) probe(ctx context.Context, j job) (bool, error) {
	if len(p.proxies) == 0 {
		return p.probeDirect(ctx, j)
	}
	ctx, cancel := p.withTimeout(ctx)
	defer cancel()
	px, err := p.nextProxy()
	if err != nil {
		return false, err
	}

	conn, err := p.dial(ctx, "tcp", px.addr)
	if err != nil {
		return false, nil // proxy unreachable → treat as closed result
	}
	defer conn.Close()

	if p.timeout > 0 {
		if err := conn.SetDeadline(time.Now().Add(p.timeout)); err != nil {
			return false, err
		}
	}

	target := net.JoinHostPort(j.ip, strconv.Itoa(j.port))
	switch px.typ {
	case "socks5":
		return socks.Handshake5(conn, target) == nil, nil
	case "http":
		return httpConnectOpen(conn, target), nil
	default: // socks4 / socks4a
		return socks.Handshake4(conn, target) == nil, nil
	}
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

// httpConnectOpen tunnels a CONNECT through an HTTP proxy over an established conn: a 2xx
// status means the proxy opened a connection to target (port open). Anything else — 403/405
// (CONNECT disabled), 502/503/504 (unreachable) — is closed. Many http proxies restrict
// CONNECT to 443, so they contribute fewer hits; the ones allowing arbitrary CONNECT widen
// egress substantially.
func httpConnectOpen(conn net.Conn, target string) bool {
	req := "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		return false
	}
	// Read only the status line; a 2xx is enough to conclude the port is open.
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return false
	}
	// "HTTP/1.1 200 Connection established" → fields[1] is the 3-digit status code.
	fields := strings.Fields(line)
	return len(fields) >= 2 && len(fields[1]) == 3 && fields[1][0] == '2'
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
