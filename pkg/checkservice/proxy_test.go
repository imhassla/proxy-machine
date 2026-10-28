package checkservice

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func splice(a, b net.Conn) {
	defer a.Close()
	defer b.Close()
	done := make(chan struct{})
	go func() { _, _ = io.Copy(a, b); _ = a.Close(); close(done) }()
	_, _ = io.Copy(b, a)
	_ = b.Close()
	<-done
}

func ownedConnectProxy(t *testing.T, tlsProxy bool) (string, *atomic.Int64) {
	t.Helper()
	count := new(atomic.Int64)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "CONNECT" {
			http.Error(w, "CONNECT required", 405)
			return
		}
		up, err := net.DialTimeout("tcp", r.Host, time.Second)
		if err != nil {
			http.Error(w, "dial failed", 502)
			return
		}
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			_ = up.Close()
			return
		}
		count.Add(1)
		_, _ = io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
		splice(&bufferedConn{conn, rw.Reader}, up)
	})
	ts := httptest.NewUnstartedServer(handler)
	if tlsProxy {
		ts.TLS = &tls.Config{NextProtos: []string{"http/1.1"}}
		ts.StartTLS()
	} else {
		ts.Start()
	}
	t.Cleanup(ts.Close)
	return ts.URL, count
}

func ownedSocksProxy(t *testing.T, version byte) (string, *atomic.Int64) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	count := new(atomic.Int64)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
				r := bufio.NewReader(conn)
				v, err := r.ReadByte()
				if err != nil || v != version {
					return
				}
				var host string
				var port uint16
				if version == 5 {
					n, err := r.ReadByte()
					if err != nil {
						return
					}
					if _, err = io.CopyN(io.Discard, r, int64(n)); err != nil {
						return
					}
					_, _ = conn.Write([]byte{5, 0})
					h := make([]byte, 4)
					if _, err = io.ReadFull(r, h); err != nil || h[1] != 1 {
						return
					}
					switch h[3] {
					case 1:
						b := make([]byte, 4)
						if _, err = io.ReadFull(r, b); err != nil {
							return
						}
						host = net.IP(b).String()
					case 3:
						n, err := r.ReadByte()
						if err != nil {
							return
						}
						b := make([]byte, n)
						if _, err = io.ReadFull(r, b); err != nil {
							return
						}
						host = string(b)
					default:
						return
					}
					if err = binary.Read(r, binary.BigEndian, &port); err != nil {
						return
					}
				} else {
					h := make([]byte, 7)
					if _, err := io.ReadFull(r, h); err != nil || h[0] != 1 {
						return
					}
					port = binary.BigEndian.Uint16(h[1:3])
					host = net.IP(h[3:7]).String()
					if _, err = r.ReadString(0); err != nil {
						return
					}
					if h[3] == 0 && h[4] == 0 && h[5] == 0 && h[6] != 0 {
						domain, err := r.ReadString(0)
						if err != nil {
							return
						}
						host = strings.TrimSuffix(domain, "\x00")
					}
				}
				up, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(int(port))), time.Second)
				if err != nil {
					return
				}
				count.Add(1)
				if version == 5 {
					_, _ = conn.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
				} else {
					_, _ = conn.Write([]byte{0, 90, 0, 0, 0, 0, 0, 0})
				}
				_ = conn.SetDeadline(time.Time{})
				splice(&bufferedConn{conn, r}, up)
			}()
		}
	}()
	return fmt.Sprintf("socks%d://%s", version, ln.Addr()), count
}

func TestOwnedDeepChecksThroughEveryProxyType(t *testing.T) {
	_, _, c := ownedFixture(t)
	for _, typ := range []string{"http", "https", "socks4", "socks5"} {
		t.Run(typ, func(t *testing.T) {
			var proxy string
			var count *atomic.Int64
			switch typ {
			case "http", "https":
				proxy, count = ownedConnectProxy(t, typ == "https")
			case "socks4":
				proxy, count = ownedSocksProxy(t, 4)
			case "socks5":
				proxy, count = ownedSocksProxy(t, 5)
			}
			if _, err := c.Probe(context.Background(), proxy, time.Second, true); err != nil {
				t.Fatal(err)
			}
			if count.Load() != 3 {
				t.Fatalf("GET/POST/WS must all traverse the proxy, got %d tunnels", count.Load())
			}
		})
	}
}
