package relay

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"proxymachine/config"
)

// --- test fixtures --------------------------------------------------------------------

// startEcho starts a TCP server that echoes everything it receives, and returns its
// host:port. It is the tunnel "target".
func startEcho(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { _, _ = io.Copy(c, c); _ = c.Close() }(c)
		}
	}()
	return ln.Addr().String()
}

// startConnectProxy starts a minimal HTTP proxy that only handles CONNECT: it dials the
// requested target and splices. Returns its host:port. Used as an "http" upstream.
func startConnectProxy(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				br := bufio.NewReader(c)
				req, err := http.ReadRequest(br)
				if err != nil || req.Method != http.MethodConnect {
					_, _ = io.WriteString(c, "HTTP/1.1 405 Method Not Allowed\r\n\r\n")
					_ = c.Close()
					return
				}
				up, err := net.Dial("tcp", req.Host)
				if err != nil {
					_, _ = io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
					_ = c.Close()
					return
				}
				_, _ = io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n")
				// Forward anything the client already buffered past the headers.
				if n := br.Buffered(); n > 0 {
					b, _ := br.Peek(n)
					_, _ = up.Write(b)
				}
				pipe(c, up)
			}(c)
		}
	}()
	return ln.Addr().String()
}

// startSocks5Upstream starts a SOCKS5 server (reusing SocksServer) that dials targets
// DIRECTLY, standing in for an upstream socks5 proxy. Returns its host:port.
func startSocks5Upstream(t *testing.T) string {
	t.Helper()
	srv := NewSocks("127.0.0.1:0", "", "", 5*time.Second, func(ctx context.Context, target string) (net.Conn, error) {
		return net.Dial("tcp", target)
	})
	go func() { _ = srv.Start() }()
	t.Cleanup(func() { _ = srv.Stop(context.Background()) })
	waitAddr(t, srv)
	return srv.Addr().String()
}

func waitAddr(t *testing.T, s *SocksServer) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if s.Addr() != nil {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("socks server did not bind in time")
}

// relayWithUpstreams builds a Server via New (so s.srv.Handler is the real wiring — this
// is what catches routing regressions like CONNECT) whose selector serves the given typed
// upstreams, bypassing the checker/db.
func relayWithUpstreams(t *testing.T, cache map[string][]string) *Server {
	t.Helper()
	s := New(&config.Config{RelayAddr: "127.0.0.1:0", MaxFailover: 5, Timeout: 5 * time.Second}, nil, nil)
	s.selector = newSelector(&fakeManager{cache: cache}, nil)
	if err := s.selector.refresh(context.Background()); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	return s
}

// --- dialUpstream (client protocols) --------------------------------------------------

func TestDialUpstreamHTTPConnect(t *testing.T) {
	echo := startEcho(t)
	proxy := startConnectProxy(t)

	conn, err := dialUpstream(context.Background(), "http://"+proxy, echo, 3*time.Second)
	if err != nil {
		t.Fatalf("dialUpstream http: %v", err)
	}
	defer conn.Close()
	assertEcho(t, conn)
}

func TestDialUpstreamSocks5(t *testing.T) {
	echo := startEcho(t)
	socksUp := startSocks5Upstream(t)

	conn, err := dialUpstream(context.Background(), "socks5://"+socksUp, echo, 3*time.Second)
	if err != nil {
		t.Fatalf("dialUpstream socks5: %v", err)
	}
	defer conn.Close()
	assertEcho(t, conn)
}

func assertEcho(t *testing.T, conn net.Conn) {
	t.Helper()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	msg := "hello-tunnel"
	if _, err := io.WriteString(conn, msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != msg {
		t.Fatalf("echo = %q, want %q", buf, msg)
	}
}

// --- HTTP CONNECT through the relay (handleConnect, full stack) ------------------------

func TestRelayConnectTunnel(t *testing.T) {
	echo := startEcho(t)
	proxy := startConnectProxy(t)
	s := relayWithUpstreams(t, map[string][]string{"http": {proxy}})

	ts := httptest.NewServer(s.srv.Handler)
	defer ts.Close()
	relayAddr := strings.TrimPrefix(ts.URL, "http://")

	conn, err := net.Dial("tcp", relayAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// Send CONNECT to the echo target through the relay.
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", echo, echo)
	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read status: %v", err)
	}
	if !strings.Contains(status, "200") {
		t.Fatalf("CONNECT status = %q, want 200", strings.TrimSpace(status))
	}
	// Consume the blank line ending the headers.
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if strings.TrimSpace(line) == "" {
			break
		}
	}
	// Tunnel is open — echo through it.
	msg := "through-connect"
	if _, err := io.WriteString(conn, msg); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(br, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(buf) != msg {
		t.Fatalf("tunnel echo = %q, want %q", buf, msg)
	}
}

// CONNECT with no working upstream returns 502 (not a hang / not a half-open hijack).
func TestRelayConnectNoUpstream(t *testing.T) {
	s := relayWithUpstreams(t, map[string][]string{"http": {"127.0.0.1:1"}}) // dead
	ts := httptest.NewServer(s.srv.Handler)
	defer ts.Close()

	conn, err := net.Dial("tcp", strings.TrimPrefix(ts.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
	br := bufio.NewReader(conn)
	status, _ := br.ReadString('\n')
	if !strings.Contains(status, "502") {
		t.Fatalf("no-upstream CONNECT status = %q, want 502", strings.TrimSpace(status))
	}
}

// --- Client SOCKS5 listener (SocksServer, full stack) ---------------------------------

func TestRelaySocksListenerEndToEnd(t *testing.T) {
	echo := startEcho(t)
	proxy := startConnectProxy(t)

	cfg := &config.Config{RelayAddr: "127.0.0.1:0", SocksAddr: "127.0.0.1:0", MaxFailover: 5, Timeout: 5 * time.Second}
	s := New(cfg, nil, nil)
	// Inject the upstream (New's selector is empty without a manager/db).
	s.selector = newSelector(&fakeManager{cache: map[string][]string{"http": {proxy}}}, nil)
	if err := s.selector.refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	socks := s.Socks()
	if socks == nil {
		t.Fatal("Socks() is nil despite SocksAddr set")
	}
	go func() { _ = socks.Start() }()
	t.Cleanup(func() { _ = socks.Stop(context.Background()) })
	waitAddr(t, socks)

	// Speak SOCKS5 to the listener using our own client, tunneling to the echo target.
	conn, err := net.Dial("tcp", socks.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := socks5Connect(conn, echo); err != nil {
		t.Fatalf("socks5 client handshake: %v", err)
	}
	assertEcho(t, conn)
}

// The SOCKS5 listener enforces username/password auth when configured.
func TestSocksListenerAuth(t *testing.T) {
	echo := startEcho(t)
	srv := NewSocks("127.0.0.1:0", "user", "pass", 5*time.Second, func(ctx context.Context, target string) (net.Conn, error) {
		return net.Dial("tcp", target)
	})
	go func() { _ = srv.Start() }()
	t.Cleanup(func() { _ = srv.Stop(context.Background()) })
	waitAddr(t, srv)
	addr := srv.Addr().String()

	// No-auth offer is rejected (server wants user/pass → 0xFF).
	c1, _ := net.Dial("tcp", addr)
	defer c1.Close()
	_, _ = c1.Write([]byte{0x05, 0x01, 0x00}) // only no-auth offered
	rep := make([]byte, 2)
	if _, err := io.ReadFull(c1, rep); err != nil {
		t.Fatal(err)
	}
	if rep[0] != 0x05 || rep[1] != 0xFF {
		t.Fatalf("no-auth offer: reply = %v, want [5 255]", rep)
	}

	// Correct credentials → CONNECT succeeds and echoes.
	c2, _ := net.Dial("tcp", addr)
	defer c2.Close()
	if err := socks5ClientAuth(c2, "user", "pass"); err != nil {
		t.Fatalf("auth: %v", err)
	}
	if err := socks5ConnectAfterAuth(c2, echo); err != nil {
		t.Fatalf("connect after auth: %v", err)
	}
	assertEcho(t, c2)

	// Wrong credentials → auth failure (status 0x01).
	c3, _ := net.Dial("tcp", addr)
	defer c3.Close()
	if err := socks5ClientAuth(c3, "user", "wrong"); err == nil {
		t.Fatal("wrong creds accepted")
	}
}

// socks5ClientAuth negotiates the username/password method and runs RFC 1929 auth.
func socks5ClientAuth(conn net.Conn, user, pass string) error {
	if _, err := conn.Write([]byte{0x05, 0x01, 0x02}); err != nil { // offer user/pass
		return err
	}
	rep := make([]byte, 2)
	if _, err := io.ReadFull(conn, rep); err != nil {
		return err
	}
	if rep[1] != 0x02 {
		return fmt.Errorf("server did not select user/pass (got %d)", rep[1])
	}
	msg := []byte{0x01, byte(len(user))}
	msg = append(msg, user...)
	msg = append(msg, byte(len(pass)))
	msg = append(msg, pass...)
	if _, err := conn.Write(msg); err != nil {
		return err
	}
	ar := make([]byte, 2)
	if _, err := io.ReadFull(conn, ar); err != nil {
		return err
	}
	if ar[1] != 0x00 {
		return fmt.Errorf("auth rejected (status %d)", ar[1])
	}
	return nil
}

// socks5ConnectAfterAuth sends only the CONNECT request+reply (auth already done).
func socks5ConnectAfterAuth(conn net.Conn, target string) error {
	host, portStr, _ := net.SplitHostPort(target)
	port := 0
	fmt.Sscanf(portStr, "%d", &port)
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, host...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := conn.Write(req); err != nil {
		return err
	}
	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		return err
	}
	if head[1] != 0x00 {
		return fmt.Errorf("connect rep %d", head[1])
	}
	var n int
	switch head[3] {
	case 0x01:
		n = 4
	case 0x04:
		n = 16
	case 0x03:
		l := make([]byte, 1)
		io.ReadFull(conn, l)
		n = int(l[0])
	}
	io.ReadFull(conn, make([]byte, n+2))
	return nil
}
