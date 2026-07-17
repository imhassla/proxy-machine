// Package socks provides minimal SOCKS4/4a and SOCKS5 CONNECT clients (no external
// dependencies). net/http can proxy http/https/socks5 but NOT socks4, so this package is
// what lets both the checker (validate socks4 anonymously) and the relay (egress through
// socks4/socks5 upstreams) use SOCKS proxies uniformly.
package socks

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

// Dial5 dials proxyAddr and opens a SOCKS5 CONNECT tunnel to target ("host:port"). The ctx
// deadline (if any) bounds the dial + handshake; the returned tunnel has no deadline.
func Dial5(ctx context.Context, proxyAddr, target string) (net.Conn, error) {
	return dial(ctx, proxyAddr, target, Handshake5)
}

// Dial4 dials proxyAddr and opens a SOCKS4/4a CONNECT tunnel to target.
func Dial4(ctx context.Context, proxyAddr, target string) (net.Conn, error) {
	return dial(ctx, proxyAddr, target, Handshake4)
}

func dial(ctx context.Context, proxyAddr, target string, handshake func(net.Conn, string) error) (net.Conn, error) {
	// KeepAlive lets the OS detect a silently-dead SOCKS proxy/peer so a stalled tunnel's
	// Read eventually errors instead of blocking forever.
	d := &net.Dialer{KeepAlive: 30 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("dial socks proxy %s: %w", proxyAddr, err)
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	if err := handshake(conn, target); err != nil {
		_ = conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

func splitTarget(target string) (host string, port int, err error) {
	h, ps, err := net.SplitHostPort(target)
	if err != nil {
		return "", 0, fmt.Errorf("invalid target %q: %w", target, err)
	}
	p, err := strconv.Atoi(ps)
	if err != nil || p < 1 || p > 65535 {
		return "", 0, fmt.Errorf("invalid target port %q", ps)
	}
	return h, p, nil
}

// Handshake5 performs a no-auth SOCKS5 CONNECT to target over an established conn.
func Handshake5(conn net.Conn, target string) error {
	host, port, err := splitTarget(target)
	if err != nil {
		return err
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

// Handshake4 performs a SOCKS4 (IPv4 target) or SOCKS4a (hostname target) CONNECT over an
// established conn. IPv6 targets are unsupported by the SOCKS4 protocol and rejected.
func Handshake4(conn net.Conn, target string) error {
	host, port, err := splitTarget(target)
	if err != nil {
		return err
	}

	req := []byte{0x04, 0x01} // VN=4, CD=CONNECT
	pb := make([]byte, 2)
	binary.BigEndian.PutUint16(pb, uint16(port))
	req = append(req, pb...)

	if ip := net.ParseIP(host); ip != nil {
		v4 := ip.To4()
		if v4 == nil {
			return fmt.Errorf("socks4 does not support IPv6 target %q", host)
		}
		req = append(req, v4...)
		req = append(req, 0x00) // empty USERID, null-terminated
	} else {
		// SOCKS4a: an "impossible" DSTIP 0.0.0.x (x!=0) signals the server to resolve the
		// hostname appended after the (null-terminated) USERID.
		if len(host) > 255 {
			return fmt.Errorf("socks4a target host too long")
		}
		req = append(req, 0x00, 0x00, 0x00, 0x01) // 0.0.0.1
		req = append(req, 0x00)                   // empty USERID
		req = append(req, host...)
		req = append(req, 0x00) // null-terminated hostname
	}
	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("socks4 connect request: %w", err)
	}

	// Reply is exactly 8 bytes: VN(0x00), CD, DSTPORT(2), DSTIP(4). CD 0x5a = granted.
	resp := make([]byte, 8)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return fmt.Errorf("socks4 connect reply: %w", err)
	}
	if resp[0] != 0x00 || resp[1] != 0x5a {
		return fmt.Errorf("socks4 connect failed (vn=%d cd=%d)", resp[0], resp[1])
	}
	return nil
}
