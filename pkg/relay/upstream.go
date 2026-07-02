package relay

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"proxymachine/pkg/socks"
)

// dialUpstream opens a raw TCP tunnel to `target` (host:port) THROUGH the upstream proxy
// `candidate` ("type://addr"). It supports every upstream scheme the checker validates:
// http/https proxies (HTTP CONNECT), socks5 and socks4/4a (SOCKS CONNECT). The returned
// conn carries bytes end-to-end to the target — the caller pipes client traffic over it
// (used for client CONNECT tunnels and the SOCKS5 listener). timeout bounds the dial +
// handshake only; the tunnel itself is not deadline-limited by this function.
func dialUpstream(ctx context.Context, candidate, target string, timeout time.Duration) (net.Conn, error) {
	u := proxyURL(candidate)
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	dctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// SOCKS upstreams: the socks package dials + handshakes and returns the tunnel.
	switch u.Scheme {
	case "socks5":
		return socks.Dial5(dctx, u.Host, target)
	case "socks4":
		return socks.Dial4(dctx, u.Host, target)
	}

	// http/https upstreams: dial the proxy, then HTTP CONNECT to the target.
	d := &net.Dialer{}
	conn, err := d.DialContext(dctx, "tcp", u.Host)
	if err != nil {
		return nil, fmt.Errorf("dial upstream %s: %w", u.Host, err)
	}
	if dl, ok := dctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	if u.Scheme == "https" {
		// TLS to the PROXY hop. Free proxies routinely present self-signed/mismatched
		// certs, so verifying here would reject most of them; the end-to-end TLS the client
		// runs INSIDE the tunnel is unaffected and still authenticates the real target.
		tconn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, ServerName: hostOnly(u.Host)})
		if err := tconn.HandshakeContext(dctx); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("tls handshake to https proxy: %w", err)
		}
		conn = tconn
	}
	if conn, err = httpConnect(conn, target); err != nil {
		_ = conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

func hostOnly(hostPort string) string {
	if h, _, err := net.SplitHostPort(hostPort); err == nil {
		return h
	}
	return hostPort
}

// httpConnect performs an HTTP CONNECT handshake to tunnel to target through an already
// dialed http/https proxy conn. It returns the conn positioned at the start of the tunnel
// stream — if the proxy pipelined bytes after the 200, they are preserved by wrapping.
func httpConnect(conn net.Conn, target string) (net.Conn, error) {
	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Connection: keep-alive\r\n\r\n", target, target)
	if _, err := io.WriteString(conn, req); err != nil {
		return conn, fmt.Errorf("write CONNECT: %w", err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		return conn, fmt.Errorf("read CONNECT response: %w", err)
	}
	if resp.Body != nil {
		_ = resp.Body.Close()
	}
	if resp.StatusCode != http.StatusOK {
		return conn, fmt.Errorf("upstream CONNECT refused: %s", resp.Status)
	}
	// The bufio.Reader may hold tunnel bytes read past the 200 headers — front them so the
	// caller's first Read doesn't lose data.
	if n := br.Buffered(); n > 0 {
		peek, _ := br.Peek(n)
		buffered := make([]byte, n)
		copy(buffered, peek)
		return &prefixConn{Conn: conn, r: io.MultiReader(bytes.NewReader(buffered), conn)}, nil
	}
	return conn, nil
}

// prefixConn is a net.Conn whose reads come from r (buffered bytes then the raw conn),
// so tunnel data a proxy pipelined ahead of the handshake boundary isn't lost.
type prefixConn struct {
	net.Conn
	r io.Reader
}

func (p *prefixConn) Read(b []byte) (int, error) { return p.r.Read(b) }

// pipe copies bytes bidirectionally between two conns until either side closes/errs, then
// tears both down. Used for client CONNECT tunnels and SOCKS5 relays.
func pipe(a, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		// Unblock the other direction: a deadline in the past collapses the peer's Read.
		_ = dst.SetDeadline(time.Now())
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
	<-done
	_ = a.Close()
	_ = b.Close()
}
