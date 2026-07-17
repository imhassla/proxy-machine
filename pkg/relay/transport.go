package relay

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"proxymachine/pkg/socks"
)

type transportPool struct {
	mu        sync.Mutex
	clients   map[string]*http.Client
	maxIdle   int
	keepAlive time.Duration
	timeout   time.Duration
}

func newTransportPool(timeout time.Duration) *transportPool {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &transportPool{
		clients:   make(map[string]*http.Client),
		maxIdle:   10,
		keepAlive: 30 * time.Second,
		timeout:   timeout,
	}
}

// proxyURL parses an upstream target into a proxy URL the http.Transport can dial. The
// selector hands "type://addr" (http/https/socks5); a bare "host:port" (legacy / direct
// registration) defaults to http for back-compat.
func proxyURL(target string) *url.URL {
	if !strings.Contains(target, "://") {
		return &url.URL{Scheme: "http", Host: target}
	}
	if u, err := url.Parse(target); err == nil && u.Host != "" {
		return u
	}
	return &url.URL{Scheme: "http", Host: target}
}

// get returns the pooled client for an upstream target ("type://addr"), keyed by the
// full target so the same host under different schemes gets distinct clients.
func (p *transportPool) get(target string) *http.Client {
	p.mu.Lock()
	defer p.mu.Unlock()

	if client, ok := p.clients[target]; ok {
		return client
	}

	u := proxyURL(target)
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: p.keepAlive,
		}).DialContext,
		MaxIdleConns:        p.maxIdle,
		MaxIdleConnsPerHost: p.maxIdle,
		IdleConnTimeout:     90 * time.Second,
		ForceAttemptHTTP2:   false,
	}
	if u.Scheme == "socks4" {
		// net/http.Transport.Proxy supports http/https/socks5 but NOT socks4. For a socks4
		// upstream, dial the request's target THROUGH the socks4 proxy ourselves (socks4a
		// resolves hostnames) instead of setting Proxy — otherwise every socks4 candidate on
		// the plaintext-HTTP relay path would fail and burn the failover budget.
		proxyHost := u.Host
		transport.DialContext = func(ctx context.Context, _, target string) (net.Conn, error) {
			return socks.Dial4(ctx, proxyHost, target)
		}
	} else {
		transport.Proxy = http.ProxyURL(u)
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   p.timeout,
	}

	p.clients[target] = client
	return client
}

func (p *transportPool) close() {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, client := range p.clients {
		client.CloseIdleConnections()
	}
	p.clients = make(map[string]*http.Client)
}
