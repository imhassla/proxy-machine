package relay

import (
	"bufio"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"proxymachine/config"
)

func websocketOrigin(t *testing.T) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !headerToken(r.Header, "Connection", "upgrade") || r.Header.Get("Upgrade") != "websocket" {
			http.Error(w, "missing upgrade", 400)
			return
		}
		c, br, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer c.Close()
		h := sha1.Sum([]byte(r.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
		fmt.Fprintf(c, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: %s\r\n\r\n", base64.StdEncoding.EncodeToString(h[:]))
		for {
			var head [2]byte
			if _, err := io.ReadFull(br, head[:]); err != nil {
				return
			}
			if head[1]&127 > 125 || head[1]&128 == 0 {
				return
			}
			var mask [4]byte
			if _, err := io.ReadFull(br, mask[:]); err != nil {
				return
			}
			p := make([]byte, int(head[1]&127))
			if _, err := io.ReadFull(br, p); err != nil {
				return
			}
			for i := range p {
				p[i] ^= mask[i%4]
			}
			if _, err := c.Write(append([]byte{0x81, byte(len(p))}, p...)); err != nil {
				return
			}
		}
	}))
	t.Cleanup(s.Close)
	return s
}

func maskedFrame(payload string) []byte {
	mask := []byte{1, 2, 3, 4}
	out := append([]byte{0x81, 0x80 | byte(len(payload))}, mask...)
	for i, b := range []byte(payload) {
		out = append(out, b^mask[i%4])
	}
	return out
}

func TestPlainWebSocketUpgradeBuffersLifetimeAndShutdown(t *testing.T) {
	origin := websocketOrigin(t)
	s := relayWithUpstreams(t, map[string][]string{"socks5": {startSocks5Upstream(t)}})
	s.timeout = 200 * time.Millisecond
	relay := httptest.NewServer(s.srv.Handler)
	defer relay.Close()
	u, _ := url.Parse(relay.URL)
	c, err := net.Dial("tcp", u.Host)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	request := fmt.Sprintf("GET %s/ws HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n", origin.URL, strings.TrimPrefix(origin.URL, "http://"))
	// Pipelined client frame must survive the relay's hijack buffer.
	c.Write(append([]byte(request), maskedFrame("first")...))
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, &http.Request{Method: "GET"})
	if err != nil || resp.StatusCode != 101 {
		t.Fatalf("upgrade: %+v %v", resp, err)
	}
	if resp.Header.Get("Sec-WebSocket-Accept") != "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" {
		t.Fatal(resp.Header)
	}
	assertFrame := func(text string) {
		t.Helper()
		b := make([]byte, len(text)+2)
		if _, err := io.ReadFull(br, b); err != nil || b[0] != 0x81 || string(b[2:]) != text {
			t.Fatalf("echo %q: %x %v", text, b, err)
		}
	}
	assertFrame("first")
	time.Sleep(250 * time.Millisecond)
	c.Write(maskedFrame("after-deadline"))
	assertFrame("after-deadline")
	if err := s.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := br.ReadByte(); err == nil {
		t.Fatal("shutdown left upgraded tunnel open")
	}
}

func TestPipeIdleActivityInEitherDirection(t *testing.T) {
	client, down := net.Pipe()
	up, origin := net.Pipe()
	defer client.Close()
	defer origin.Close()
	done := make(chan struct{})
	go func() { pipeStreams(down, down, up, 100*time.Millisecond); close(done) }()
	// Only server-to-client traffic is active. Independent read deadlines would kill it.
	for i := 0; i < 5; i++ {
		go origin.Write([]byte("x"))
		client.SetReadDeadline(time.Now().Add(time.Second))
		var b [1]byte
		if _, err := io.ReadFull(client, b[:]); err != nil {
			t.Fatal(err)
		}
		time.Sleep(30 * time.Millisecond)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("silent stream was not reaped")
	}
}

func TestRelayDoesNotFollowOriginRedirect(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "http://must-not-be-requested.invalid/")
		w.WriteHeader(302)
	}))
	defer up.Close()
	s := relayWithUpstreams(t, map[string][]string{"http": {strings.TrimPrefix(up.URL, "http://")}})
	w := httptest.NewRecorder()
	s.handleRequest(w, httptest.NewRequest("GET", "http://origin.example/", nil))
	if w.Code != 302 || w.Header().Get("Location") != "http://must-not-be-requested.invalid/" {
		t.Fatal(w)
	}
}

func TestUDPDisabledByConfiguration(t *testing.T) {
	s := New(&config.Config{SocksAddr: "127.0.0.1:0", UDPMode: "off"}, nil, nil, nil)
	srv := s.Socks()
	go srv.Start()
	defer srv.Stop(context.Background())
	waitAddr(t, srv)
	c, err := net.Dial("tcp", srv.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(time.Second))
	c.Write([]byte{5, 1, 0})
	var greeting [2]byte
	io.ReadFull(c, greeting[:])
	c.Write([]byte{5, cmdUDPAssociate, 0, 1, 127, 0, 0, 1, 0, 53})
	var reply [10]byte
	if _, err := io.ReadFull(c, reply[:]); err != nil {
		t.Fatal(err)
	}
	if reply[1] != repCmdNotSupported {
		t.Fatal(reply)
	}
}
