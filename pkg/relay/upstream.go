package relay

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"
)

// dialUpstream opens a raw TCP tunnel to `target` (host:port) THROUGH the upstream proxy
// `candidate` ("type://addr"). It supports the three upstream schemes the checker
// validates: http/https proxies (HTTP CONNECT) and socks5 (SOCKS5 CONNECT). The returned
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

	d := &net.Dialer{}
	conn, err := d.DialContext(dctx, "tcp", u.Host)
	if err != nil {
		return nil, fmt.Errorf("dial upstream %s: %w", u.Host, err)
	}
	// Bound the handshake by the same deadline, then clear it so the caller owns an
	// unrestricted tunnel.
	if dl, ok := dctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}

	switch u.Scheme {
	case "socks5":
		if err := socks5Connect(conn, target); err != nil {
			_ = conn.Close()
			return nil, err
		}
	case "https":
		// TLS to the PROXY hop. Free proxies routinely present self-signed/mismatched
		// certs, so verifying here would reject most of them; the end-to-end TLS the client
		// runs INSIDE the tunnel is unaffected and still authenticates the real target.
		tconn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, ServerName: hostOnly(u.Host)})
		if err := tconn.HandshakeContext(dctx); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("tls handshake to https proxy: %w", err)
		}
		conn = tconn
		if conn, err = httpConnect(conn, target); err != nil {
			_ = conn.Close()
			return nil, err
		}
	default: // http (and bare host:port)
		if conn, err = httpConnect(conn, target); err != nil {
			_ = conn.Close()
			return nil, err
		}
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

// socks5Connect performs a no-auth SOCKS5 CONNECT to target through an already dialed
// socks5 proxy conn. Minimal client: greeting → CONNECT request → reply.
func socks5Connect(conn net.Conn, target string) error {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return fmt.Errorf("invalid target %q: %w", target, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("invalid target port %q", portStr)
	}

	// Greeting: VER=5, one method, NO-AUTH(0x00).
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return fmt.Errorf("socks5 greeting: %w", err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return fmt.Errorf("socks5 greeting reply: %w", err)
	}
	if reply[0] != 0x05 || reply[1] != 0x00 {
		return fmt.Errorf("socks5 no-auth rejected (ver=%d method=%d)", reply[0], reply[1])
	}

	// Request: VER=5, CMD=CONNECT(1), RSV=0, then ATYP+ADDR+PORT.
	buf := []byte{0x05, 0x01, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			buf = append(buf, 0x01)
			buf = append(buf, v4...)
		} else {
			buf = append(buf, 0x04)
			buf = append(buf, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return fmt.Errorf("socks5 target host too long")
		}
		buf = append(buf, 0x03, byte(len(host)))
		buf = append(buf, host...)
	}
	p := make([]byte, 2)
	binary.BigEndian.PutUint16(p, uint16(port))
	buf = append(buf, p...)
	if _, err := conn.Write(buf); err != nil {
		return fmt.Errorf("socks5 connect request: %w", err)
	}

	// Reply: VER, REP, RSV, ATYP, BND.ADDR, BND.PORT — REP==0 is success.
	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		return fmt.Errorf("socks5 connect reply: %w", err)
	}
	if head[1] != 0x00 {
		return fmt.Errorf("socks5 connect failed (rep=%d)", head[1])
	}
	// Drain BND.ADDR + BND.PORT so the stream is positioned at the tunnel start.
	var addrLen int
	switch head[3] {
	case 0x01:
		addrLen = 4
	case 0x04:
		addrLen = 16
	case 0x03:
		l := make([]byte, 1)
		if _, err := io.ReadFull(conn, l); err != nil {
			return fmt.Errorf("socks5 bnd addr len: %w", err)
		}
		addrLen = int(l[0])
	default:
		return fmt.Errorf("socks5 unknown bnd atyp %d", head[3])
	}
	if _, err := io.ReadFull(conn, make([]byte, addrLen+2)); err != nil {
		return fmt.Errorf("socks5 bnd addr/port: %w", err)
	}
	return nil
}

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
