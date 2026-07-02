package relay

import (
	"context"
	"crypto/subtle"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"sync"
	"time"

	"proxymachine/metrics"
)

// SocksServer is a client-facing SOCKS5 proxy: clients point their socks5:// at it and it
// tunnels each CONNECT through a rotating, validated upstream proxy (the same selection +
// health + failover path the HTTP relay uses, via the injected dial func). Only the
// CONNECT command is supported (BIND/UDP-ASSOCIATE are rejected). When user is set,
// username/password auth (RFC 1929) is required; otherwise no-auth is offered. Bind
// defaults to loopback so a fresh install is not an open SOCKS proxy.
type SocksServer struct {
	addr       string
	user, pass string
	timeout    time.Duration
	dial       func(ctx context.Context, target string) (net.Conn, error)
	metrics    *metrics.Metrics

	mu     sync.Mutex
	ln     net.Listener
	conns  map[net.Conn]struct{}
	closed bool
}

// NewSocks builds a SOCKS5 server. dial opens a tunnel to a "host:port" target through an
// upstream (typically relay.Server.dialTunnel).
func NewSocks(addr, user, pass string, timeout time.Duration, m *metrics.Metrics, dial func(ctx context.Context, target string) (net.Conn, error)) *SocksServer {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &SocksServer{
		addr:    addr,
		user:    user,
		pass:    pass,
		timeout: timeout,
		dial:    dial,
		metrics: m,
		conns:   make(map[net.Conn]struct{}),
	}
}

// Start binds and serves until Stop. It blocks; a graceful Stop returns nil, a real listen
// error is returned (so the caller can fail fast).
func (s *SocksServer) Start() error {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return err
	}
	if s.user == "" && !isLoopbackAddr(s.addr) {
		log.Printf("WARNING: SOCKS5 bound to %s with no proxyUser — this is an OPEN PROXY reachable from the network; set proxyUser/proxyPass or bind to loopback", s.addr)
	}
	s.mu.Lock()
	s.ln = ln
	s.mu.Unlock()
	for {
		conn, err := ln.Accept()
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed {
				return nil
			}
			return err
		}
		go s.handle(conn)
	}
}

// Addr returns the actual listen address (useful when binding to :0), or nil before Start.
func (s *SocksServer) Addr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ln == nil {
		return nil
	}
	return s.ln.Addr()
}

// Stop closes the listener and all in-flight tunnels. Idempotent.
func (s *SocksServer) Stop(_ context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if s.ln != nil {
		_ = s.ln.Close()
	}
	for c := range s.conns {
		_ = c.Close()
	}
	return nil
}

func (s *SocksServer) track(c net.Conn, add bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if add {
		if s.closed { // racing shutdown — don't keep a conn we won't close
			_ = c.Close()
			return
		}
		s.conns[c] = struct{}{}
		return
	}
	delete(s.conns, c)
}

func (s *SocksServer) handle(conn net.Conn) {
	s.track(conn, true)
	defer func() {
		s.track(conn, false)
		_ = conn.Close()
	}()

	// The handshake must not hang a client slot forever; the tunnel clears the deadline.
	_ = conn.SetDeadline(time.Now().Add(s.timeout))

	if err := s.handshake(conn); err != nil {
		return // errors are per-client; nothing to surface
	}
	target, err := s.readConnectRequest(conn)
	if err != nil {
		return
	}
	s.metrics.IncRelaySocks()

	// Tunnel phase: no artificial deadline (connections can be long-lived).
	_ = conn.SetDeadline(time.Time{})
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	upstream, derr := s.dial(ctx, target)
	cancel()
	if derr != nil {
		s.metrics.IncRelayFailure()
		_ = writeReply(conn, repHostUnreachable)
		return
	}
	if err := writeReply(conn, repSucceeded); err != nil {
		_ = upstream.Close()
		return
	}
	pipe(conn, upstream)
}

// SOCKS5 reply codes (subset).
const (
	repSucceeded       = 0x00
	repGeneralFailure  = 0x01
	repHostUnreachable = 0x04
	repCmdNotSupported = 0x07
)

// handshake performs the method-negotiation (and username/password sub-negotiation when
// auth is enabled).
func (s *SocksServer) handshake(conn net.Conn) error {
	head := make([]byte, 2)
	if _, err := io.ReadFull(conn, head); err != nil {
		return err
	}
	if head[0] != 0x05 {
		return fmt.Errorf("not socks5 (ver=%d)", head[0])
	}
	methods := make([]byte, int(head[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}

	want := byte(0x00) // no-auth
	if s.user != "" {
		want = 0x02 // username/password
	}
	if !containsByte(methods, want) {
		_, _ = conn.Write([]byte{0x05, 0xFF}) // no acceptable methods
		return fmt.Errorf("client did not offer method %d", want)
	}
	if _, err := conn.Write([]byte{0x05, want}); err != nil {
		return err
	}
	if want == 0x02 {
		return s.authUserPass(conn)
	}
	return nil
}

// authUserPass runs RFC 1929 username/password sub-negotiation.
func (s *SocksServer) authUserPass(conn net.Conn) error {
	ver := make([]byte, 2) // VER, ULEN
	if _, err := io.ReadFull(conn, ver); err != nil {
		return err
	}
	if ver[0] != 0x01 {
		return fmt.Errorf("bad auth version %d", ver[0])
	}
	uname := make([]byte, int(ver[1]))
	if _, err := io.ReadFull(conn, uname); err != nil {
		return err
	}
	plen := make([]byte, 1)
	if _, err := io.ReadFull(conn, plen); err != nil {
		return err
	}
	passwd := make([]byte, int(plen[0]))
	if _, err := io.ReadFull(conn, passwd); err != nil {
		return err
	}
	ok := subtle.ConstantTimeCompare(uname, []byte(s.user)) == 1 &&
		subtle.ConstantTimeCompare(passwd, []byte(s.pass)) == 1
	if !ok {
		_, _ = conn.Write([]byte{0x01, 0x01}) // failure
		return fmt.Errorf("auth failed")
	}
	_, err := conn.Write([]byte{0x01, 0x00}) // success
	return err
}

// readConnectRequest parses the SOCKS5 request and returns the "host:port" target. Only
// CONNECT is supported; other commands get a reply and an error.
func (s *SocksServer) readConnectRequest(conn net.Conn) (string, error) {
	head := make([]byte, 4) // VER, CMD, RSV, ATYP
	if _, err := io.ReadFull(conn, head); err != nil {
		return "", err
	}
	if head[0] != 0x05 {
		return "", fmt.Errorf("bad request version %d", head[0])
	}
	if head[1] != 0x01 { // CONNECT only
		_ = writeReply(conn, repCmdNotSupported)
		return "", fmt.Errorf("unsupported command %d", head[1])
	}

	var host string
	switch head[3] {
	case 0x01: // IPv4
		b := make([]byte, 4)
		if _, err := io.ReadFull(conn, b); err != nil {
			return "", err
		}
		host = net.IP(b).String()
	case 0x04: // IPv6
		b := make([]byte, 16)
		if _, err := io.ReadFull(conn, b); err != nil {
			return "", err
		}
		host = net.IP(b).String()
	case 0x03: // domain
		l := make([]byte, 1)
		if _, err := io.ReadFull(conn, l); err != nil {
			return "", err
		}
		b := make([]byte, int(l[0]))
		if _, err := io.ReadFull(conn, b); err != nil {
			return "", err
		}
		host = string(b)
	default:
		_ = writeReply(conn, repGeneralFailure)
		return "", fmt.Errorf("bad atyp %d", head[3])
	}

	pb := make([]byte, 2)
	if _, err := io.ReadFull(conn, pb); err != nil {
		return "", err
	}
	port := int(pb[0])<<8 | int(pb[1])
	return net.JoinHostPort(host, strconv.Itoa(port)), nil
}

// writeReply sends a SOCKS5 reply with a zero BND.ADDR/PORT (IPv4 form).
func writeReply(conn net.Conn, rep byte) error {
	_, err := conn.Write([]byte{0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	return err
}

func containsByte(b []byte, x byte) bool {
	for _, v := range b {
		if v == x {
			return true
		}
	}
	return false
}
