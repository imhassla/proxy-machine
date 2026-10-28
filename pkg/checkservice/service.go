// Package checkservice provides signed, bounded proxy checks behind an existing
// xrok HTTPS tunnel. The service never fetches URLs supplied by visitors.
package checkservice

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

const maxBody = 64 << 10

type Observation struct {
	Version  int               `json:"version"`
	Nonce    string            `json:"nonce"`
	Origin   string            `json:"origin"`
	Headers  map[string]string `json:"headers"`
	Method   string            `json:"method"`
	Received int               `json:"received"`
	SHA256   string            `json:"sha256"`
}

type envelope struct {
	Payload   []byte `json:"payload"`
	Signature []byte `json:"signature"`
}

type Service struct {
	key         ed25519.PrivateKey
	path        string
	mu          sync.Mutex
	closed      bool
	connections map[*websocket.Conn]struct{}
	slots       chan struct{}
}

func New() (*Service, error) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	path := make([]byte, 16)
	if _, err := rand.Read(path); err != nil {
		return nil, err
	}
	return &Service{key: key, path: "/" + hex.EncodeToString(path), connections: make(map[*websocket.Conn]struct{}), slots: make(chan struct{}, 128)}, nil
}

// Close also closes upgraded connections, which http.Server.Shutdown cannot.
func (s *Service) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	for c := range s.connections {
		_ = c.Close()
	}
}

// Descriptor pins the service signing key. Its fragment never travels in HTTP.
func (s *Service) Descriptor(base string) string {
	return strings.TrimRight(base, "/") + s.path + "#" + base64.RawURLEncoding.EncodeToString(s.key.Public().(ed25519.PublicKey))
}

func (s *Service) signed(o Observation) envelope {
	payload, _ := json.Marshal(o)
	return envelope{payload, ed25519.Sign(s.key, payload)}
}

func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		http.Error(w, "busy", 503)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.Path != s.path+"/probe" && r.URL.Path != s.path+"/ws" {
		http.NotFound(w, r)
		return
	}
	nonce := r.URL.Query().Get("nonce")
	if len(nonce) != 32 {
		http.Error(w, "invalid nonce", 400)
		return
	}
	if _, err := hex.DecodeString(nonce); err != nil {
		http.Error(w, "invalid nonce", 400)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.WriteHeader(405)
		return
	}
	// Only the loopback xrok child can reach this listener. Current xrok replaces
	// X-Real-IP with its socket peer; fail closed if that metadata is missing.
	origin := strings.TrimSpace(r.Header.Get("X-Real-IP"))
	if net.ParseIP(origin) == nil {
		http.Error(w, "xrok origin metadata missing", 503)
		return
	}
	headers := make(map[string]string)
	for _, name := range []string{"Via", "Forwarded", "Client-IP", "X-Client-IP", "X-Forwarded"} {
		if v := strings.Join(r.Header.Values(name), ", "); v != "" {
			headers[name] = v
		}
	}
	// Remove only xrok's appended peer, retaining a proxy's original chain.
	xff := strings.Join(r.Header.Values("X-Forwarded-For"), ",")
	parts := strings.Split(xff, ",")
	if len(parts) > 0 && strings.TrimSpace(parts[len(parts)-1]) == origin {
		if v := strings.TrimSpace(strings.Join(parts[:len(parts)-1], ",")); v != "" {
			headers["X-Forwarded-For"] = v
		}
	}
	o := Observation{Version: 1, Nonce: nonce, Origin: origin, Headers: headers, Method: r.Method}
	var body []byte
	if r.URL.Path == s.path+"/ws" {
		if !websocket.IsWebSocketUpgrade(r) {
			http.Error(w, "upgrade required", 400)
			return
		}
		u := websocket.Upgrader{ReadBufferSize: 1024, WriteBufferSize: 1024}
		conn, err := u.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			return
		}
		s.connections[conn] = struct{}{}
		s.mu.Unlock()
		defer func() { s.mu.Lock(); delete(s.connections, conn); s.mu.Unlock() }()
		conn.SetReadLimit(maxBody)
		_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		kind, payload, err := conn.ReadMessage()
		if err != nil || kind != websocket.BinaryMessage {
			return
		}
		body = payload
		o.Method = "WEBSOCKET"
		o.Received = len(body)
		sum := sha256.Sum256(body)
		o.SHA256 = hex.EncodeToString(sum[:])
		_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		_ = conn.WriteJSON(s.signed(o))
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	var err error
	body, err = readBounded(r.Body, maxBody)
	if err != nil {
		http.Error(w, "body too large or incomplete", 413)
		return
	}
	o.Received = len(body)
	sum := sha256.Sum256(body)
	o.SHA256 = hex.EncodeToString(sum[:])
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s.signed(o))
}

func (o Observation) VerifyBody(method string, body []byte) error {
	sum := sha256.Sum256(body)
	if o.Version != 1 || o.Method != method || o.Received != len(body) || o.SHA256 != hex.EncodeToString(sum[:]) || net.ParseIP(o.Origin) == nil {
		return fmt.Errorf("invalid signed observation")
	}
	return nil
}
