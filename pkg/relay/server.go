package relay

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"proxymachine/checker"
	"proxymachine/config"
	"proxymachine/db"
	"proxymachine/metrics"
)

// relayRefreshInterval is how often the relay re-reads the selector's candidate set from
// the checker's liveness view, so dead upstreams leave the rotation and freshly validated
// ones enter it (the snapshot would otherwise freeze after the first fill).
const relayRefreshInterval = 15 * time.Second

// maxRequestBody caps a relayed request body. The body is buffered in full (to replay
// across failover candidates), so an unbounded read would be a memory-exhaustion DoS.
const maxRequestBody = 32 << 20 // 32 MiB

// perAttemptDial caps a SINGLE upstream dial+handshake in a tunnel, so a dead proxy that
// hangs (rather than refusing) can't eat the whole request budget before failover reaches
// a live one. maxFailover bounds the COUNT of attempts; this bounds each one's TIME.
const perAttemptDial = 8 * time.Second

// Server is an HTTP proxy relay that forwards client requests through
// currently alive upstream HTTP/HTTPS proxies.
type Server struct {
	manager    *checker.CheckManager
	db         *db.DB
	user, pass string // when user != "", require Proxy-Authorization Basic

	srv      *http.Server
	stopOnce sync.Once
	done     chan struct{} // closed by Stop to end the background refresh loop

	selector     *selector
	pool         *transportPool
	timeout      time.Duration
	maxAttempts  int // upstream proxies tried per request before giving up
	socks        *SocksServer
	metrics      *metrics.Metrics
	stickyHeader string
	sticky       *stickyStore
}

// New creates a relay server from config: it listens on cfg.RelayAddr (default
// 127.0.0.1:3333 — NOT an open proxy), uses cfg.Timeout per request, and requires
// Basic Proxy-Authorization when cfg.ProxyUser is set. The *http.Server is built here
// (not in Start) so Stop always has a non-nil server — closing the race where a shutdown
// signal arriving during startup would make Stop a no-op and hang ListenAndServe forever.
func New(cfg *config.Config, manager *checker.CheckManager, database *db.DB, m *metrics.Metrics) *Server {
	if cfg == nil {
		cfg = &config.Config{}
	}
	addr := cfg.RelayAddr
	if addr == "" {
		addr = "127.0.0.1:3333"
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	maxAttempts := cfg.MaxFailover
	if maxAttempts <= 0 {
		maxAttempts = 5
	}
	s := &Server{
		manager:     manager,
		db:          database,
		user:        cfg.ProxyUser,
		pass:        cfg.ProxyPass,
		timeout:     timeout,
		maxAttempts: maxAttempts,
		metrics:     m,
		done:        make(chan struct{}),
	}
	if cfg.StickyHeader != "" {
		s.stickyHeader = cfg.StickyHeader
		s.sticky = newStickyStore(cfg.StickyTTL)
	}
	// Convert nil concrete pointers to genuinely-nil interfaces: a (*CheckManager)(nil)
	// or (*db.DB)(nil) stored directly would be a non-nil interface holding a nil value,
	// so the selector's `!= nil` guards would pass and then panic on a nil-receiver call.
	var psrc proxySource
	if manager != nil {
		psrc = manager
	}
	var dsrc dbSource
	if database != nil {
		dsrc = database
	}
	s.selector = newSelector(psrc, dsrc)
	s.pool = newTransportPool(timeout)

	// Loud warning if this would be an OPEN proxy: bound to a non-loopback address with
	// no Proxy-Authorization required. The defaults are loopback, so this only fires when
	// an operator widens the bind without setting credentials.
	if cfg.ProxyUser == "" && !isLoopbackAddr(addr) {
		log.Printf("WARNING: relay bound to %s with no proxyUser — this is an OPEN PROXY reachable from the network; set proxyUser/proxyPass or bind to loopback", addr)
	}

	// A forward proxy must handle CONNECT, whose request-target is authority-form
	// ("host:port", no leading "/"). http.ServeMux routes by path and 404s such requests
	// before the handler runs, so the relay serves a single HandlerFunc directly.
	s.srv = &http.Server{
		Addr:              addr,
		Handler:           http.HandlerFunc(s.handleRequest),
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      timeout + 5*time.Second,
		IdleTimeout:       120 * time.Second,
		ReadHeaderTimeout: 2 * time.Second,
	}

	// Optional client-facing SOCKS5 listener, tunneling through the same rotating,
	// health-ranked upstreams as the HTTP relay. Empty SocksAddr disables it.
	if cfg.SocksAddr != "" {
		s.socks = NewSocks(cfg.SocksAddr, cfg.ProxyUser, cfg.ProxyPass, timeout, m, s.socksDial)
	}
	return s
}

// Socks returns the client-facing SOCKS5 server, or nil if SocksAddr was empty. The caller
// runs its Start/Stop lifecycle alongside the HTTP relay.
func (s *Server) Socks() *SocksServer { return s.socks }

// isLoopbackAddr reports whether a listen address binds only the loopback interface.
// A bare ":port" / "0.0.0.0:port" / a public host counts as non-loopback (reachable).
func isLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	if host == "" {
		return false // ":3333" binds all interfaces
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Start begins listening for HTTP requests. It blocks until the server stops.
func (s *Server) Start() error {
	// Best-effort warm-up, then keep the candidate set in sync with the checker.
	_ = s.selector.refresh(context.Background())
	go s.refreshLoop()
	return s.srv.ListenAndServe()
}

// refreshLoop periodically re-reads the selector's candidate set until Stop.
func (s *Server) refreshLoop() {
	t := time.NewTicker(relayRefreshInterval)
	defer t.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-t.C:
			_ = s.selector.refresh(context.Background())
		}
	}
}

// Stop gracefully shuts down the server and closes idle connections. It is safe to call
// more than once (idempotent).
func (s *Server) Stop(ctx context.Context) error {
	err := s.srv.Shutdown(ctx)
	s.stopOnce.Do(func() {
		close(s.done)
		s.pool.close()
	})
	return err
}

// authOK reports whether the request carries valid Basic Proxy-Authorization when auth
// is enabled. Comparison is constant-time. The credential is never forwarded upstream —
// Proxy-Authorization is in the hop-by-hop strip set.
func (s *Server) authOK(r *http.Request) bool {
	if s.user == "" {
		return true
	}
	const prefix = "Basic "
	h := r.Header.Get("Proxy-Authorization")
	if !strings.HasPrefix(h, prefix) {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(h, prefix))
	if err != nil {
		return false
	}
	u, p, ok := strings.Cut(string(raw), ":")
	if !ok {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(u), []byte(s.user)) == 1 &&
		subtle.ConstantTimeCompare([]byte(p), []byte(s.pass)) == 1
}

// stickyKeyFor returns the session-affinity key for a request (the configured header's
// value), or "" when stickiness is disabled or the header is absent.
func (s *Server) stickyKeyFor(r *http.Request) string {
	if s.sticky == nil || s.stickyHeader == "" {
		return ""
	}
	return r.Header.Get(s.stickyHeader)
}

func (s *Server) handleRequest(w http.ResponseWriter, r *http.Request) {
	if !s.authOK(r) {
		w.Header().Set("Proxy-Authenticate", `Basic realm="proxy-machine"`)
		http.Error(w, "proxy authentication required", http.StatusProxyAuthRequired)
		return
	}

	// CONNECT is an HTTPS (or any-TCP) tunnel request: establish a byte pipe to the target
	// THROUGH a rotating upstream, then splice the client to it. This is what makes the
	// relay usable for HTTPS traffic, not just plaintext HTTP.
	if r.Method == http.MethodConnect {
		s.handleConnect(w, r)
		return
	}

	s.metrics.IncRelayHTTP()
	ctx, cancel := context.WithTimeout(r.Context(), s.timeout)
	defer cancel()

	var candidates []string
	addr, cands, err := s.selector.next(ctx)
	if err != nil {
		if err := s.selector.refresh(ctx); err != nil {
			s.metrics.IncRelayFailure()
			http.Error(w, fmt.Sprintf("no proxy available: %v", err), http.StatusServiceUnavailable)
			return
		}
		addr, cands, err = s.selector.next(ctx)
		if err != nil {
			s.metrics.IncRelayFailure()
			http.Error(w, fmt.Sprintf("no proxy available: %v", err), http.StatusServiceUnavailable)
			return
		}
	}
	if len(cands) > 0 {
		candidates = cands // already rotated to start at the round-robin pick
	} else if addr != "" {
		candidates = []string{addr}
	}

	// Session affinity: if this request's session is pinned to an upstream, try it first
	// (failover to the rest still applies if it's dead).
	stickyKey := s.stickyKeyFor(r)
	if stickyKey != "" {
		if pinned := s.sticky.get(stickyKey); pinned != "" {
			candidates = moveToFront(candidates, pinned)
		}
	}

	// Buffer the original body exactly once (and preserve length) so every candidate
	// attempt receives the body with correct ContentLength, and replay works across
	// proxies after errors. Bounded by MaxBytesReader so a client can't OOM the relay
	// by streaming an unbounded body (the buffer is held for the whole failover loop).
	var bodyBytes []byte
	if r.Body != nil {
		var err error
		bodyBytes, err = io.ReadAll(http.MaxBytesReader(w, r.Body, maxRequestBody))
		r.Body.Close()
		if err != nil {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
	}

	// Bound the failover walk: without this a request against a DB full of dead proxies
	// would try every one until the request timeout elapsed. maxAttempts<=0 means unbounded.
	maxAttempts := s.maxAttempts
	if maxAttempts <= 0 {
		maxAttempts = len(candidates)
	}
	var lastErr error
	attempts := 0
	for _, proxyAddr := range candidates {
		if attempts >= maxAttempts {
			break
		}
		attempts++
		client := s.pool.get(proxyAddr)

		outURL := r.URL
		var bodyReader io.Reader
		if bodyBytes != nil {
			bodyReader = bytes.NewReader(bodyBytes)
		}
		outReq, err := http.NewRequestWithContext(ctx, r.Method, outURL.String(), bodyReader)
		if err != nil {
			http.Error(w, fmt.Sprintf("create request: %v", err), http.StatusInternalServerError)
			return
		}
		if bodyBytes != nil {
			outReq.ContentLength = int64(len(bodyBytes))
			outReq.GetBody = func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(bodyBytes)), nil
			}
		} else {
			outReq.ContentLength = r.ContentLength
		}

		for key, values := range r.Header {
			for _, v := range values {
				outReq.Header.Add(key, v)
			}
		}
		stripHopByHop(outReq.Header)

		start := time.Now()
		resp, err := client.Do(outReq)
		// Feed the outcome to the health tracker so future selections prefer this upstream
		// (on success, by latency) or back off from it (circuit breaker on repeated fails).
		s.selector.report(proxyAddr, err == nil, time.Since(start))
		s.metrics.AddUpstream(err == nil)
		if err != nil {
			lastErr = err
			// Fail over to the next upstream ONLY for idempotent/safe methods. A
			// client.Do error can occur AFTER the request reached the target and the
			// side effect ran (e.g. the response read failed), so replaying a POST/PATCH
			// through another proxy could duplicate the mutation.
			if !idempotentMethod(r.Method) {
				break
			}
			continue
		}

		// Reached an upstream successfully — pin this session to it for future requests.
		if stickyKey != "" {
			s.sticky.set(stickyKey, proxyAddr)
		}

		stripHopByHop(resp.Header)
		for key, values := range resp.Header {
			for _, v := range values {
				w.Header().Add(key, v)
			}
		}
		w.WriteHeader(resp.StatusCode)

		if _, err := io.Copy(w, resp.Body); err != nil {
			resp.Body.Close()
			return
		}
		resp.Body.Close()
		return
	}

	s.metrics.IncRelayFailure()
	if lastErr != nil {
		http.Error(w, fmt.Sprintf("proxy request failed: %v", lastErr), http.StatusBadGateway)
		return
	}
	http.Error(w, "proxy request failed: all upstreams failed", http.StatusBadGateway)
}

// handleConnect services an HTTP CONNECT: it opens a byte tunnel to r.Host through a
// rotating upstream, replies 200, and splices the hijacked client conn to it. This lets a
// browser/curl send HTTPS (or any TCP) through the relay, tunneled over the upstream proxy.
func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	s.metrics.IncRelayConnect()
	target := r.Host
	if target == "" {
		target = r.URL.Host
	}
	if _, _, err := net.SplitHostPort(target); err != nil {
		s.metrics.IncRelayFailure()
		http.Error(w, "invalid CONNECT target", http.StatusBadRequest)
		return
	}

	// Dial the upstream BEFORE hijacking, so a dial failure is a clean HTTP error response
	// rather than a half-open hijacked connection.
	stickyKey := s.stickyKeyFor(r)
	pinned := ""
	if stickyKey != "" {
		pinned = s.sticky.get(stickyKey)
	}
	dctx, cancel := context.WithTimeout(r.Context(), s.timeout)
	upstream, used, err := s.dialTunnel(dctx, target, pinned)
	cancel()
	if err != nil {
		s.metrics.IncRelayFailure()
		http.Error(w, fmt.Sprintf("connect failed: %v", err), http.StatusBadGateway)
		return
	}
	if stickyKey != "" {
		s.sticky.set(stickyKey, used)
	}

	hij, ok := w.(http.Hijacker)
	if !ok {
		_ = upstream.Close()
		http.Error(w, "connect unsupported", http.StatusInternalServerError)
		return
	}
	clientConn, brw, err := hij.Hijack()
	if err != nil {
		_ = upstream.Close()
		return
	}
	// We own the conn now; a tunnel can be long-lived, so drop the server's I/O deadlines.
	_ = clientConn.SetDeadline(time.Time{})
	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		_ = clientConn.Close()
		_ = upstream.Close()
		return
	}

	// The client may have pipelined bytes after CONNECT (e.g. the TLS ClientHello) into the
	// hijack buffer. Drain them and front them so the tunnel doesn't lose the handshake.
	var clientReader io.Reader = clientConn
	if brw != nil && brw.Reader.Buffered() > 0 {
		n := brw.Reader.Buffered()
		pre := make([]byte, n)
		if _, err := io.ReadFull(brw.Reader, pre); err == nil {
			clientReader = io.MultiReader(bytes.NewReader(pre), clientConn)
		}
	}
	pipe(&prefixConn{Conn: clientConn, r: clientReader}, upstream)
}

// socksDial adapts dialTunnel to the SOCKS listener's dial signature (no session affinity:
// the SOCKS protocol carries no per-request header to key a sticky session on).
func (s *Server) socksDial(ctx context.Context, target string) (net.Conn, error) {
	conn, _, err := s.dialTunnel(ctx, target, "")
	return conn, err
}

// dialTunnel opens a tunnel to target through the best available upstreams, trying at most
// maxAttempts and recording each outcome in the health tracker. `preferred` (a pinned
// sticky upstream) is tried first when present. Returns the upstream that succeeded so the
// caller can record session affinity. Shared by the CONNECT handler and the SOCKS listener.
func (s *Server) dialTunnel(ctx context.Context, target, preferred string) (net.Conn, string, error) {
	_, cands, err := s.selector.next(ctx)
	if err != nil {
		if rerr := s.selector.refresh(ctx); rerr != nil {
			return nil, "", rerr
		}
		if _, cands, err = s.selector.next(ctx); err != nil {
			return nil, "", err
		}
	}
	if preferred != "" {
		cands = moveToFront(cands, preferred)
	}
	maxAttempts := s.maxAttempts
	if maxAttempts <= 0 {
		maxAttempts = len(cands)
	}
	attemptTimeout := s.timeout
	if attemptTimeout <= 0 || attemptTimeout > perAttemptDial {
		attemptTimeout = perAttemptDial
	}
	var lastErr error
	attempts := 0
	for _, cand := range cands {
		if attempts >= maxAttempts {
			break
		}
		attempts++
		start := time.Now()
		conn, derr := dialUpstream(ctx, cand, target, attemptTimeout)
		s.selector.report(cand, derr == nil, time.Since(start))
		s.metrics.AddUpstream(derr == nil)
		if derr == nil {
			return conn, cand, nil
		}
		lastErr = derr
	}
	if lastErr != nil {
		return nil, "", lastErr
	}
	return nil, "", ErrNoProxyAvailable
}

// idempotentMethod reports whether an HTTP method is safe to replay across upstreams on
// a transport error. POST/PATCH are excluded so failover can never duplicate a
// non-idempotent side effect. PUT/DELETE are included because they are idempotent per
// RFC 7231 §4.2.2 (repeat delivery yields the same effect) — this is broader than
// net/http.Transport, which auto-retries only GET/HEAD/OPTIONS/TRACE.
func idempotentMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace, http.MethodPut, http.MethodDelete:
		return true
	default:
		return false
	}
}

var hopByHop = map[string]struct{}{
	"Connection":          {},
	"Proxy-Connection":    {}, // non-standard but widely sent by clients; must not be forwarded
	"Keep-Alive":          {},
	"Proxy-Authenticate":  {},
	"Proxy-Authorization": {},
	"TE":                  {},
	"Trailer":             {},
	"Transfer-Encoding":   {},
	"Upgrade":             {},
}

func stripHopByHop(h http.Header) {
	if c := h.Get("Connection"); c != "" {
		for _, f := range strings.Split(c, ",") {
			f = strings.TrimSpace(f)
			if f != "" {
				h.Del(f)
			}
		}
	}
	for k := range hopByHop {
		h.Del(k)
	}
	h.Del("Connection")
}
