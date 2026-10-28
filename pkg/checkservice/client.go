package checkservice

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"proxymachine/pkg/socks"
)

type Client struct {
	base      string
	key       ed25519.PublicKey
	roots     *x509.CertPool
	timeout   time.Duration
	healthMu  sync.Mutex
	healthAt  time.Time
	healthErr error
}

func NewClient(descriptor, caFile string, timeout time.Duration) (*Client, error) {
	u, err := url.Parse(descriptor)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || strings.Trim(u.Path, "/") == "" {
		return nil, fmt.Errorf("check service requires an HTTPS descriptor with path and signing-key fragment")
	}
	key, err := base64.RawURLEncoding.DecodeString(u.Fragment)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid check service signing key")
	}
	u.Fragment = ""
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	c := &Client{base: strings.TrimRight(u.String(), "/"), key: ed25519.PublicKey(key), timeout: timeout}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read check service CA: %w", err)
		}
		c.roots, err = x509.SystemCertPool()
		if err != nil {
			c.roots = x509.NewCertPool()
		}
		if !c.roots.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("check service CA contains no certificates")
		}
	}
	return c, nil
}

func readBounded(r io.Reader, max int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("response too large")
	}
	return b, nil
}

func (c *Client) transport(proxy string, connectTimeout time.Duration) (*http.Transport, error) {
	if connectTimeout <= 0 {
		connectTimeout = c.timeout
	}
	d := &net.Dialer{Timeout: connectTimeout}
	t := &http.Transport{DialContext: d.DialContext, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: c.roots}, TLSHandshakeTimeout: connectTimeout, MaxResponseHeaderBytes: 32 << 10, DisableKeepAlives: true}
	if proxy == "" {
		return t, nil
	} // Deliberately bypass HTTP(S)_PROXY environment.
	u, err := url.Parse(proxy)
	if err != nil || u.Hostname() == "" || u.Port() == "" || u.User != nil {
		return nil, fmt.Errorf("invalid proxy URL")
	}
	switch u.Scheme {
	case "socks4", "socks4a", "socks5", "socks5h", "http", "https":
		t.DialContext = func(ctx context.Context, network, target string) (net.Conn, error) {
			ctx, cancel := context.WithTimeout(ctx, connectTimeout)
			defer cancel()
			switch u.Scheme {
			case "socks4", "socks4a":
				return socks.Dial4(ctx, u.Host, target)
			case "socks5", "socks5h":
				return socks.Dial5(ctx, u.Host, target)
			default:
				return c.connect(ctx, u, target)
			}
		}
	default:
		return nil, fmt.Errorf("unsupported proxy scheme")
	}
	return t, nil
}

func nonce() (string, error) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	return hex.EncodeToString(b), err
}

func (c *Client) verify(body []byte, n string) (Observation, error) {
	var e envelope
	var o Observation
	if err := json.Unmarshal(body, &e); err != nil {
		return o, err
	}
	if !ed25519.Verify(c.key, e.Payload, e.Signature) {
		return o, fmt.Errorf("invalid check service signature")
	}
	if err := json.Unmarshal(e.Payload, &o); err != nil {
		return o, err
	}
	if o.Nonce != n {
		return o, fmt.Errorf("check service nonce mismatch")
	}
	return o, nil
}

func (c *Client) exchange(ctx context.Context, t *http.Transport, method string, payload []byte) (Observation, error) {
	var empty Observation
	n, err := nonce()
	if err != nil {
		return empty, err
	}
	u := c.base + "/probe?nonce=" + n
	req, err := http.NewRequestWithContext(ctx, method, u, bytes.NewReader(payload))
	if err != nil {
		return empty, err
	}
	h := &http.Client{Transport: t, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := h.Do(req)
	if err != nil {
		return empty, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return empty, fmt.Errorf("check service HTTP status %d", resp.StatusCode)
	}
	b, err := readBounded(resp.Body, 32<<10)
	if err != nil {
		return empty, err
	}
	o, err := c.verify(b, n)
	if err != nil {
		return empty, err
	}
	return o, o.VerifyBody(method, payload)
}

// Probe verifies a fresh signed response and optionally a POST and WebSocket
// payload. One context budget covers all operations; no redirects or fallback.
func (c *Client) Probe(ctx context.Context, proxy string, connectTimeout time.Duration, deep bool) (Observation, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	t, err := c.transport(proxy, connectTimeout)
	if err != nil {
		return Observation{}, err
	}
	defer t.CloseIdleConnections()
	o, err := c.exchange(ctx, t, "GET", nil)
	if err != nil || !deep {
		return o, err
	}
	payload := make([]byte, maxBody)
	if _, err = rand.Read(payload); err != nil {
		return o, err
	}
	if _, err = c.exchange(ctx, t, "POST", payload); err != nil {
		return o, err
	}
	err = c.websocket(ctx, t, payload[:64])
	return o, err
}

func (c *Client) websocket(ctx context.Context, t *http.Transport, payload []byte) error {
	n, err := nonce()
	if err != nil {
		return err
	}
	d := websocket.Dialer{Proxy: t.Proxy, NetDialContext: t.DialContext, TLSClientConfig: t.TLSClientConfig, HandshakeTimeout: c.timeout}
	conn, resp, err := d.DialContext(ctx, "wss"+strings.TrimPrefix(c.base, "https")+"/ws?nonce="+n, nil)
	if err != nil {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		return err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetReadDeadline(deadline)
		_ = conn.SetWriteDeadline(deadline)
	}
	// Close is concurrency-safe; changing Gorilla's write deadline from a
	// cancellation callback would race a blocked WriteMessage.
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	conn.SetReadLimit(32 << 10)
	if err := conn.WriteMessage(websocket.BinaryMessage, payload); err != nil {
		return err
	}
	k, b, err := conn.ReadMessage()
	if err != nil {
		return err
	}
	if k != websocket.TextMessage {
		return fmt.Errorf("invalid WebSocket response")
	}
	o, err := c.verify(b, n)
	if err != nil {
		return err
	}
	return o.VerifyBody("WEBSOCKET", payload)
}

// Healthy coalesces concurrent failure diagnostics. Negative results are cached
// briefly; a previous successful check cannot hide a subsequent tunnel outage.
func (c *Client) Healthy(ctx context.Context) bool {
	started := time.Now()
	c.healthMu.Lock()
	defer c.healthMu.Unlock()
	if c.healthAt.After(started) || (c.healthErr != nil && time.Since(c.healthAt) < time.Second) {
		return c.healthErr == nil
	}
	_, c.healthErr = c.Probe(ctx, "", 0, false)
	c.healthAt = time.Now()
	return c.healthErr == nil
}
