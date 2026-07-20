package relay

import (
	"net"
	"strconv"
	"sync"
)

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

	// client → target: decapsulate and forward.
	go func() {
		buf := make([]byte, 64*1024)
		for {
			n, from, err := client.ReadFromUDP(buf)
			if err != nil {
				return
			}
			mu.Lock()
			clientAddr = from
			mu.Unlock()
			host, port, data, ok := parseUDPHeader(buf[:n])
			if !ok {
				continue
			}
			dst, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, strconv.Itoa(port)))
			if err != nil {
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
			mu.Lock()
			ca := clientAddr
			mu.Unlock()
			if ca == nil {
				continue
			}
			_, _ = client.WriteToUDP(buildUDPHeader(from, buf[:n]), ca)
		}
	}()

	// The association lives as long as the TCP control connection: block until the client
	// closes it, then the deferred Closes tear down both UDP sockets and end the goroutines.
	drain := make([]byte, 1)
	for {
		if _, err := conn.Read(drain); err != nil {
			return
		}
	}
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
