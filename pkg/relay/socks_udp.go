package relay

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// udpIdleTimeout tears down a UDP association that has seen no datagram in either direction
// for this long, even if the client keeps the TCP control connection open. Without it an
// idle-but-open association pins two UDP sockets + two goroutines + buffers indefinitely, and
// there is no cap on concurrent associations.
const udpIdleTimeout = 60 * time.Second

// udpResolveTimeout bounds a per-datagram DNS lookup for a domain target so a slow/stuck
// resolver can't park the forwarding goroutine (a context-less ResolveUDPAddr isn't
// interruptible by socket close during teardown).
const udpResolveTimeout = 5 * time.Second

// handleUDPAssociate services a SOCKS5 UDP ASSOCIATE. It binds a UDP relay socket, tells the
// client where to send datagrams, then shuttles SOCKS5-UDP-encapsulated packets between the
// client and their targets for as long as the TCP control connection stays open.
//
// NOTE: our upstreams are TCP proxies and cannot carry UDP, so UDP datagrams egress DIRECTLY
// from THIS host — they are NOT anonymized through the proxy pool. This provides SOCKS5 UDP
// (DNS/QUIC) for local clients; it is not an anonymous UDP proxy.
func (s *SocksServer) handleUDPAssociate(conn net.Conn) {
	// Bind the relay socket on the same IP the client reached us on (loopback by default).
	bindIP := net.IPv4(127, 0, 0, 1)
	if la, ok := conn.LocalAddr().(*net.TCPAddr); ok {
		bindIP = la.IP
	}
	client, err := net.ListenUDP("udp", &net.UDPAddr{IP: bindIP, Port: 0})
	if err != nil {
		_ = writeReply(conn, repGeneralFailure)
		return
	}
	defer client.Close()
	egress, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		_ = writeReply(conn, repGeneralFailure)
		return
	}
	defer egress.Close()

	bnd := client.LocalAddr().(*net.UDPAddr)
	if err := writeReplyAddr(conn, repSucceeded, bnd.IP, bnd.Port); err != nil {
		return
	}

	var mu sync.Mutex
	var clientAddr *net.UDPAddr // learned from the first datagram the client sends

	// lastActive tracks the most recent datagram in either direction (unix nanos) so the idle
	// watchdog can reap a silent association.
	var lastActive atomic.Int64
	lastActive.Store(time.Now().UnixNano())

	// client → target: decapsulate and forward.
	go func() {
		buf := make([]byte, 64*1024)
		for {
			n, from, err := client.ReadFromUDP(buf)
			if err != nil {
				return
			}
			lastActive.Store(time.Now().UnixNano())
			mu.Lock()
			clientAddr = from
			mu.Unlock()
			host, port, data, ok := parseUDPHeader(buf[:n])
			if !ok {
				continue
			}
			dst := resolveUDP(host, port)
			if dst == nil {
				continue
			}
			_, _ = egress.WriteToUDP(data, dst)
		}
	}()

	// target → client: re-encapsulate replies and deliver.
	go func() {
		buf := make([]byte, 64*1024)
		for {
			n, from, err := egress.ReadFromUDP(buf)
			if err != nil {
				return
			}
			lastActive.Store(time.Now().UnixNano())
			mu.Lock()
			ca := clientAddr
			mu.Unlock()
			if ca == nil {
				continue
			}
			_, _ = client.WriteToUDP(buildUDPHeader(from, buf[:n]), ca)
		}
	}()

	// Watch the TCP control connection in the background: when the client closes it, signal
	// teardown. (conn.Read blocks with no deadline, so we can't poll it inline with the timer.)
	ctlClosed := make(chan struct{})
	go func() {
		defer close(ctlClosed)
		drain := make([]byte, 1)
		for {
			if _, err := conn.Read(drain); err != nil {
				return
			}
		}
	}()

	// The association lives until the control conn closes OR it goes idle for udpIdleTimeout.
	// Returning runs the deferred client/egress Closes (which end the two relay goroutines);
	// the caller's conn.Close() then unblocks the control-drain goroutine above.
	ticker := time.NewTicker(udpIdleTimeout / 2)
	defer ticker.Stop()
	for {
		select {
		case <-ctlClosed:
			return
		case <-ticker.C:
			if time.Since(time.Unix(0, lastActive.Load())) >= udpIdleTimeout {
				return
			}
		}
	}
}

// resolveUDP resolves a UDP target to an address, returning nil on failure. A literal IP is
// resolved inline; a domain uses the default resolver with a bounded context so a slow or
// wedged DNS lookup can't park the forwarding goroutine indefinitely (socket close during
// teardown does not interrupt a context-less lookup).
func resolveUDP(host string, port int) *net.UDPAddr {
	if ip := net.ParseIP(host); ip != nil {
		return &net.UDPAddr{IP: ip, Port: port}
	}
	ctx, cancel := context.WithTimeout(context.Background(), udpResolveTimeout)
	defer cancel()
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil || len(ips) == 0 {
		return nil
	}
	return &net.UDPAddr{IP: net.IP(ips[0].AsSlice()), Port: port}
}

// writeReplyAddr sends a SOCKS5 reply carrying a real BND.ADDR/BND.PORT (used by UDP
// ASSOCIATE to advertise the relay socket).
func writeReplyAddr(conn net.Conn, rep byte, ip net.IP, port int) error {
	reply := []byte{0x05, rep, 0x00}
	if v4 := ip.To4(); v4 != nil {
		reply = append(reply, 0x01)
		reply = append(reply, v4...)
	} else {
		reply = append(reply, 0x04)
		reply = append(reply, ip.To16()...)
	}
	reply = append(reply, byte(port>>8), byte(port))
	_, err := conn.Write(reply)
	return err
}

// parseUDPHeader decodes a SOCKS5 UDP request datagram (RSV RSV FRAG ATYP ADDR PORT DATA),
// returning the target host/port and payload. Fragmented datagrams (FRAG != 0) are dropped.
func parseUDPHeader(pkt []byte) (host string, port int, data []byte, ok bool) {
	if len(pkt) < 4 || pkt[2] != 0x00 { // need header; FRAG must be 0
		return "", 0, nil, false
	}
	i := 4
	switch pkt[3] {
	case 0x01: // IPv4
		if len(pkt) < i+4+2 {
			return "", 0, nil, false
		}
		host = net.IP(pkt[i : i+4]).String()
		i += 4
	case 0x04: // IPv6
		if len(pkt) < i+16+2 {
			return "", 0, nil, false
		}
		host = net.IP(pkt[i : i+16]).String()
		i += 16
	case 0x03: // domain
		if len(pkt) < i+1 {
			return "", 0, nil, false
		}
		l := int(pkt[i])
		i++
		if len(pkt) < i+l+2 {
			return "", 0, nil, false
		}
		host = string(pkt[i : i+l])
		i += l
	default:
		return "", 0, nil, false
	}
	port = int(pkt[i])<<8 | int(pkt[i+1])
	i += 2
	return host, port, pkt[i:], true
}

// buildUDPHeader wraps reply data in a SOCKS5 UDP header sourced at `from`.
func buildUDPHeader(from *net.UDPAddr, data []byte) []byte {
	out := []byte{0x00, 0x00, 0x00}
	if v4 := from.IP.To4(); v4 != nil {
		out = append(out, 0x01)
		out = append(out, v4...)
	} else {
		out = append(out, 0x04)
		out = append(out, from.IP.To16()...)
	}
	out = append(out, byte(from.Port>>8), byte(from.Port))
	return append(out, data...)
}
