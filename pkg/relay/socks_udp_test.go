package relay

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

// startUDPEcho starts a UDP echo server and returns its *net.UDPAddr.
func startUDPEcho(t *testing.T) *net.UDPAddr {
	t.Helper()
	ln, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := ln.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = ln.WriteToUDP(buf[:n], from)
		}
	}()
	return ln.LocalAddr().(*net.UDPAddr)
}

// End-to-end SOCKS5 UDP ASSOCIATE: negotiate over TCP, then relay a datagram to a UDP echo
// target and read the echoed reply back through the relay.
func TestSocksUDPAssociate(t *testing.T) {
	echo := startUDPEcho(t)
	srv := NewSocks("127.0.0.1:0", "", "", 5*time.Second, nil, func(ctx context.Context, target string) (net.Conn, error) {
		return net.Dial("tcp", target)
	})
	go func() { _ = srv.Start() }()
	t.Cleanup(func() { _ = srv.Stop(context.Background()) })
	waitAddr(t, srv)

	ctrl, err := net.Dial("tcp", srv.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer ctrl.Close()

	// Greeting (no-auth) + UDP ASSOCIATE.
	ctrl.Write([]byte{0x05, 0x01, 0x00})
	rep := make([]byte, 2)
	io.ReadFull(ctrl, rep)
	ctrl.Write([]byte{0x05, cmdUDPAssociate, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	head := make([]byte, 4)
	if _, err := io.ReadFull(ctrl, head); err != nil {
		t.Fatal(err)
	}
	if head[1] != repSucceeded || head[3] != 0x01 {
		t.Fatalf("UDP ASSOCIATE reply = %v, want success + IPv4", head)
	}
	ipb := make([]byte, 4)
	io.ReadFull(ctrl, ipb)
	pb := make([]byte, 2)
	io.ReadFull(ctrl, pb)
	relay := &net.UDPAddr{IP: net.IP(ipb), Port: int(pb[0])<<8 | int(pb[1])}

	// Send an encapsulated datagram to the echo target through the relay.
	uc, err := net.DialUDP("udp", nil, relay)
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()
	pkt := append([]byte{0x00, 0x00, 0x00, 0x01}, echo.IP.To4()...)
	pkt = append(pkt, byte(echo.Port>>8), byte(echo.Port))
	pkt = append(pkt, []byte("udp-ping")...)
	if _, err := uc.Write(pkt); err != nil {
		t.Fatal(err)
	}

	// Read the encapsulated echo reply.
	_ = uc.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 2048)
	n, err := uc.Read(buf)
	if err != nil {
		t.Fatalf("read UDP reply: %v", err)
	}
	_, _, data, ok := parseUDPHeader(buf[:n])
	if !ok || string(data) != "udp-ping" {
		t.Fatalf("UDP echo through relay = %q (ok=%v), want %q", data, ok, "udp-ping")
	}
}
