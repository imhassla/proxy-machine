package socks

import (
	"bufio"
	"context"
	"io"
	"net"
	"testing"
	"time"
)

// fakeSocks5 accepts a no-auth SOCKS5 CONNECT, then echoes (standing in for the target).
func fakeSocks5(t *testing.T) string {
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
				defer c.Close()
				br := bufio.NewReader(c)
				h := make([]byte, 2) // VER, NMETHODS
				if _, err := io.ReadFull(br, h); err != nil {
					return
				}
				if _, err := io.ReadFull(br, make([]byte, int(h[1]))); err != nil {
					return
				}
				c.Write([]byte{0x05, 0x00})
				req := make([]byte, 4) // VER,CMD,RSV,ATYP
				if _, err := io.ReadFull(br, req); err != nil {
					return
				}
				switch req[3] {
				case 0x01:
					io.ReadFull(br, make([]byte, 4))
				case 0x04:
					io.ReadFull(br, make([]byte, 16))
				case 0x03:
					l := make([]byte, 1)
					io.ReadFull(br, l)
					io.ReadFull(br, make([]byte, int(l[0])))
				}
				io.ReadFull(br, make([]byte, 2)) // port
				c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
				echo(br, c)
			}(c)
		}
	}()
	return ln.Addr().String()
}

// fakeSocks4 accepts a SOCKS4/4a CONNECT, then echoes. It records the resolved target host
// via the channel so a test can assert socks4a hostname passing.
func fakeSocks4(t *testing.T, gotHost chan<- string) string {
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
				defer c.Close()
				br := bufio.NewReader(c)
				head := make([]byte, 8) // VN,CD,PORT(2),IP(4)
				if _, err := io.ReadFull(br, head); err != nil {
					return
				}
				readCString(br) // USERID
				host := net.IP(head[4:8]).String()
				// socks4a: DSTIP 0.0.0.x (x != 0) means a hostname follows.
				if head[4] == 0 && head[5] == 0 && head[6] == 0 && head[7] != 0 {
					host = readCString(br)
				}
				if gotHost != nil {
					select {
					case gotHost <- host:
					default:
					}
				}
				c.Write([]byte{0x00, 0x5a, 0, 0, 0, 0, 0, 0}) // granted
				echo(br, c)
			}(c)
		}
	}()
	return ln.Addr().String()
}

func readCString(r *bufio.Reader) string {
	b, err := r.ReadBytes(0x00)
	if err != nil {
		return ""
	}
	return string(b[:len(b)-1])
}

func echo(r io.Reader, w io.Writer) { _, _ = io.Copy(w, r) }

func roundTrip(t *testing.T, conn net.Conn) {
	t.Helper()
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	msg := "socks-payload"
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

func TestDial5(t *testing.T) {
	addr := fakeSocks5(t)
	conn, err := Dial5(ctxWithTimeout(t), addr, "example.com:443")
	if err != nil {
		t.Fatalf("Dial5: %v", err)
	}
	roundTrip(t, conn)
}

func TestDial4IPv4(t *testing.T) {
	got := make(chan string, 1)
	addr := fakeSocks4(t, got)
	conn, err := Dial4(ctxWithTimeout(t), addr, "1.2.3.4:80")
	if err != nil {
		t.Fatalf("Dial4: %v", err)
	}
	if h := <-got; h != "1.2.3.4" {
		t.Fatalf("socks4 target = %q, want 1.2.3.4", h)
	}
	roundTrip(t, conn)
}

func TestDial4aHostname(t *testing.T) {
	got := make(chan string, 1)
	addr := fakeSocks4(t, got)
	conn, err := Dial4(ctxWithTimeout(t), addr, "example.com:80")
	if err != nil {
		t.Fatalf("Dial4 (4a): %v", err)
	}
	if h := <-got; h != "example.com" {
		t.Fatalf("socks4a target = %q, want example.com", h)
	}
	roundTrip(t, conn)
}

func TestHandshake4RejectsIPv6(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	go io.Copy(io.Discard, c2) // drain so a write can't block
	if err := Handshake4(c1, "[::1]:80"); err == nil {
		t.Fatal("Handshake4 accepted an IPv6 target, want error")
	}
}

func ctxWithTimeout(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	t.Cleanup(cancel)
	return ctx
}
