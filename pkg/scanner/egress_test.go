package scanner

import (
	"bufio"
	"context"
	"io"
	"net"
	"reflect"
	"testing"
	"time"
)

// serveOnce accepts exactly one connection and hands it to handler, then closes the listener.
// Returns the listener address.
func serveOnce(t *testing.T, handler func(net.Conn)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		conn, err := ln.Accept()
		_ = ln.Close()
		if err != nil {
			return
		}
		defer conn.Close()
		handler(conn)
	}()
	return ln.Addr().String()
}

// fakeSocks5 plays a minimal SOCKS5 server that grants one CONNECT (reply REP=granted).
func fakeSocks5(granted bool) func(net.Conn) {
	return func(c net.Conn) {
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		greet := make([]byte, 3) // VER NMETHODS METHOD
		if _, err := io.ReadFull(c, greet); err != nil {
			return
		}
		c.Write([]byte{0x05, 0x00}) // no-auth
		head := make([]byte, 4)     // VER CMD RSV ATYP
		if _, err := io.ReadFull(c, head); err != nil {
			return
		}
		switch head[3] {
		case 0x01:
			io.ReadFull(c, make([]byte, 4+2))
		case 0x04:
			io.ReadFull(c, make([]byte, 16+2))
		case 0x03:
			l := make([]byte, 1)
			io.ReadFull(c, l)
			io.ReadFull(c, make([]byte, int(l[0])+2))
		}
		rep := byte(0x00) // succeeded
		if !granted {
			rep = 0x05 // connection refused
		}
		c.Write([]byte{0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	}
}

// fakeHTTPProxy plays an HTTP proxy that answers a CONNECT with the given status line.
func fakeHTTPProxy(status string) func(net.Conn) {
	return func(c net.Conn) {
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		br := bufio.NewReader(c)
		for { // consume the CONNECT request headers up to the blank line
			line, err := br.ReadString('\n')
			if err != nil {
				return
			}
			if line == "\r\n" || line == "\n" {
				break
			}
		}
		c.Write([]byte("HTTP/1.1 " + status + "\r\n\r\n"))
	}
}

// A probe through a SOCKS5 proxy that grants CONNECT reports the target port OPEN; one that
// refuses reports CLOSED. This proves the scanner can egress via socks5, not just socks4.
func TestProbeThroughSocks5(t *testing.T) {
	addr := serveOnce(t, fakeSocks5(true))
	p := newProber([]scanProxy{{addr: addr, typ: "socks5"}}, 2*time.Second, nil)
	open, err := p.probe(context.Background(), job{ip: "1.2.3.4", port: 80})
	if err != nil || !open {
		t.Fatalf("socks5 grant → open: got open=%v err=%v", open, err)
	}

	addr2 := serveOnce(t, fakeSocks5(false))
	p2 := newProber([]scanProxy{{addr: addr2, typ: "socks5"}}, 2*time.Second, nil)
	if open, _ := p2.probe(context.Background(), job{ip: "1.2.3.4", port: 80}); open {
		t.Fatal("socks5 refuse → must be closed")
	}
}

// A probe through an HTTP proxy: a 200 CONNECT reply is OPEN; a 502 is CLOSED. This proves the
// scanner can egress via http proxies (those allowing arbitrary CONNECT), not only SOCKS.
func TestProbeThroughHTTPConnect(t *testing.T) {
	addr := serveOnce(t, fakeHTTPProxy("200 Connection established"))
	p := newProber([]scanProxy{{addr: addr, typ: "http"}}, 2*time.Second, nil)
	open, err := p.probe(context.Background(), job{ip: "1.2.3.4", port: 80})
	if err != nil || !open {
		t.Fatalf("http CONNECT 200 → open: got open=%v err=%v", open, err)
	}

	addr2 := serveOnce(t, fakeHTTPProxy("502 Bad Gateway"))
	p2 := newProber([]scanProxy{{addr: addr2, typ: "http"}}, 2*time.Second, nil)
	if open, _ := p2.probe(context.Background(), job{ip: "1.2.3.4", port: 80}); open {
		t.Fatal("http CONNECT 502 → must be closed")
	}
}

// screenGrantAll must drop a proxy that grants the unroutable sentinel (a liar) and keep one
// that refuses it (honest).
func TestScreenGrantAll(t *testing.T) {
	liar := serveOnce(t, fakeSocks5(true))    // grants every CONNECT, incl. the sentinel
	honest := serveOnce(t, fakeSocks5(false)) // refuses
	pool := []scanProxy{{addr: liar, typ: "socks5"}, {addr: honest, typ: "socks5"}}
	clean := screenGrantAll(context.Background(), pool, 2*time.Second)
	if len(clean) != 1 || clean[0].addr != honest {
		t.Fatalf("screen kept %v, want only the honest proxy %s", clean, honest)
	}
}

func TestDeriveNeighborhoods(t *testing.T) {
	known := []string{
		// 9.9.9.0/24 is a dense block: 3 distinct proxies, ports 8080 (x2) and 3128 (x1).
		"9.9.9.10:8080", "9.9.9.11:8080", "9.9.9.12:3128",
		// 5.5.5.0/24 is dense too: 2 proxies on 8080.
		"5.5.5.1:8080", "5.5.5.2:8080",
		// 1.2.3.0/24 has a single proxy → below minDensity=2, excluded (and its lone port
		// 4145 must not appear).
		"1.2.3.9:4145",
		// junk / non-IPv4 ignored.
		"not-an-addr", "[::1]:80",
	}
	cidrs, ports := deriveNeighborhoods(known, 2, 1, 12)

	wantCIDRs := []string{"5.5.5.0/24", "9.9.9.0/24"}
	if !reflect.DeepEqual(cidrs, wantCIDRs) {
		t.Fatalf("cidrs = %v, want %v", cidrs, wantCIDRs)
	}
	// Ports come from dense blocks only: 8080 (x4) and 3128 (x1); 4145 excluded (sparse block).
	wantPorts := []int{3128, 8080}
	if !reflect.DeepEqual(ports, wantPorts) {
		t.Fatalf("ports = %v, want %v", ports, wantPorts)
	}

	// minPortHits=2 drops the single-occurrence 3128, keeping only 8080.
	_, ports2 := deriveNeighborhoods(known, 2, 2, 12)
	if !reflect.DeepEqual(ports2, []int{8080}) {
		t.Fatalf("ports (minPortHits=2) = %v, want [8080]", ports2)
	}

	// No block meets minDensity=5 → empty result.
	c3, p3 := deriveNeighborhoods(known, 5, 1, 12)
	if len(c3) != 0 || len(p3) != 0 {
		t.Fatalf("minDensity=5 → want empty, got cidrs=%v ports=%v", c3, p3)
	}
}

// Sanity: the derived port list respects MaxPorts (top-N by recurrence).
func TestDeriveNeighborhoodsMaxPorts(t *testing.T) {
	known := []string{
		"9.9.9.1:80", "9.9.9.2:80", "9.9.9.3:81", "9.9.9.4:82",
	}
	_, ports := deriveNeighborhoods(known, 2, 1, 1) // cap to 1 → only the most recurring (80)
	if !reflect.DeepEqual(ports, []int{80}) {
		t.Fatalf("MaxPorts=1 → want [80], got %v", ports)
	}
}
