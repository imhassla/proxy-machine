package relay

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ProbeOptions controls a bounded, explicit GET to an operator-owned endpoint.
// RootCAs allows private lab certificates without disabling certificate verification.
type ProbeOptions struct {
	ExpectedSHA256 string
	RootCAs        *x509.CertPool
}

type ProbeResult struct {
	Capability
	SHA256       string `json:"sha256,omitempty"`
	BodyVerified bool   `json:"body_verified"`
}

// Probe verifies the full origin path instead of inferring application health from
// CONNECT success. It has no direct-egress fallback and never follows redirects.
func Probe(ctx context.Context, upstream, rawURL string, opts ProbeOptions) (result ProbeResult, err error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Hostname() == "" || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return result, fmt.Errorf("probe requires an http or https target without credentials")
	}
	p, err := url.Parse(upstream)
	if err == nil {
		switch p.Scheme {
		case "socks4a":
			p.Scheme = "socks4"
		case "socks5h":
			p.Scheme = "socks5"
		}
		upstream = p.String()
	}
	if err != nil || p.Hostname() == "" || p.Port() == "" || p.User != nil || (p.Scheme != "http" && p.Scheme != "https" && p.Scheme != "socks4" && p.Scheme != "socks5") {
		return result, fmt.Errorf("probe requires a typed upstream with host and port, without credentials")
	}
	if opts.ExpectedSHA256 != "" {
		digest, e := hex.DecodeString(opts.ExpectedSHA256)
		if e != nil || len(digest) != sha256.Size {
			return result, fmt.Errorf("expected SHA-256 must be 64 hex characters")
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return result, err
	}
	result.Capability = Capability{Upstream: upstream, Target: requestTarget(req), Operation: "probe", ObservedAt: start}
	defer func() {
		result.Success = err == nil
		result.LatencySeconds = time.Since(start).Seconds()
		ttl := capabilityTTL
		if err != nil {
			ttl = failureTTL
		}
		result.ExpiresAt = start.Add(ttl)
	}()
	tr := &http.Transport{DisableKeepAlives: true}
	defer tr.CloseIdleConnections()
	tr.DialContext = func(ctx context.Context, _, target string) (net.Conn, error) {
		return dialUpstream(ctx, upstream, target, 10*time.Second)
	}
	tr.DialTLSContext = func(ctx context.Context, _, target string) (net.Conn, error) {
		conn, e := dialUpstream(ctx, upstream, target, 10*time.Second)
		if e != nil {
			return nil, e
		}
		tc := tls.Client(conn, &tls.Config{ServerName: hostOnly(target), RootCAs: opts.RootCAs, MinVersion: tls.VersionTLS12})
		if e = tc.HandshakeContext(ctx); e != nil {
			conn.Close()
			return nil, &attemptError{stage: "target_tls", err: e}
		}
		return tc, nil
	}
	client := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, e := client.Do(req)
	if e != nil {
		result.Stage, result.Status = failureStage(e)
		return result, e
	}
	defer resp.Body.Close()
	result.Stage = "http_response"
	result.Status = resp.StatusCode
	if resp.StatusCode != http.StatusOK {
		return result, fmt.Errorf("probe origin status %d", resp.StatusCode)
	}
	body, e := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	result.Stage = "body"
	if e != nil {
		return result, e
	}
	if len(body) > 1<<20 {
		return result, fmt.Errorf("probe body exceeds 1 MiB")
	}
	digest := sha256.Sum256(body)
	result.SHA256 = hex.EncodeToString(digest[:])
	if opts.ExpectedSHA256 != "" {
		if result.SHA256 != strings.ToLower(opts.ExpectedSHA256) {
			return result, fmt.Errorf("probe body SHA-256 mismatch")
		}
		result.BodyVerified = true
	}
	return result, nil
}
