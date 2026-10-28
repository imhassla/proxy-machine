package relay

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

func headerToken(h http.Header, key, token string) bool {
	for _, value := range h.Values(key) {
		for _, part := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(part), token) {
				return true
			}
		}
	}
	return false
}

// Bound establishment without inheriting that deadline into a healthy upgraded stream.
func upgradeRoundTrip(parent context.Context, req *http.Request, client *http.Client, budget time.Duration) (*http.Response, error, func()) {
	streamCtx, cancel := context.WithCancel(parent)
	deadlineCtx, deadlineCancel := context.WithTimeout(parent, budget)
	stop := context.AfterFunc(deadlineCtx, cancel)
	cleanup := func() { stop(); deadlineCancel(); cancel() }
	resp, err := client.Transport.RoundTrip(req.WithContext(streamCtx))
	if err == nil && resp.StatusCode == http.StatusSwitchingProtocols {
		if !stop() {
			resp.Body.Close()
			cancel()
			err = deadlineCtx.Err()
		}
		deadlineCancel()
	}
	return resp, err, cleanup
}

func (s *Server) trackTunnel(conn net.Conn) bool {
	s.tunnelMu.Lock()
	defer s.tunnelMu.Unlock()
	select {
	case <-s.done:
		conn.Close()
		return false
	default:
	}
	if s.tunnels == nil {
		s.tunnels = make(map[net.Conn]struct{})
	}
	s.tunnels[conn] = struct{}{}
	return true
}
func (s *Server) untrackTunnel(conn net.Conn) {
	s.tunnelMu.Lock()
	delete(s.tunnels, conn)
	s.tunnelMu.Unlock()
}

func (s *Server) serveUpgrade(w http.ResponseWriter, r *http.Request, resp *http.Response) {
	defer resp.Body.Close()
	upstream, ok := resp.Body.(io.ReadWriteCloser)
	if !ok || !strings.EqualFold(resp.Header.Get("Upgrade"), "websocket") || !headerToken(resp.Header, "Connection", "upgrade") {
		http.Error(w, "invalid upstream upgrade", http.StatusBadGateway)
		return
	}
	hij, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "upgrade unsupported", 500)
		return
	}
	conn, buffer, err := hij.Hijack()
	if err != nil {
		return
	}
	defer conn.Close()
	if !s.trackTunnel(conn) {
		return
	}
	defer s.untrackTunnel(conn)
	conn.SetDeadline(time.Time{})
	stripHopByHop(resp.Header)
	resp.Header.Set("Connection", "Upgrade")
	resp.Header.Set("Upgrade", "websocket")
	if _, err = io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\n"); err != nil {
		return
	}
	if err = resp.Header.Write(conn); err != nil {
		return
	}
	if _, err = io.WriteString(conn, "\r\n"); err != nil {
		return
	}
	pipeStreams(conn, buffer, upstream, tunnelIdleTimeout)
}
