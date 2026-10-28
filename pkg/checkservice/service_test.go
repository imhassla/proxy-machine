package checkservice

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func ownedFixture(t *testing.T) (*Service, *httptest.Server, *Client) {
	t.Helper()
	s, err := New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Header.Set("X-Real-IP", "9.9.9.9")
		r.Header.Set("X-Forwarded-For", "1.2.3.4, 9.9.9.9")
		s.ServeHTTP(w, r)
	}))
	t.Cleanup(ts.Close)
	c, err := NewClient(s.Descriptor(ts.URL), "", 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	c.roots = ts.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	return s, ts, c
}

func TestSignedDeepProbeAndHeaderNormalization(t *testing.T) {
	_, _, c := ownedFixture(t)
	o, err := c.Probe(context.Background(), "", time.Second, true)
	if err != nil {
		t.Fatal(err)
	}
	if o.Origin != "9.9.9.9" || o.Headers["X-Forwarded-For"] != "1.2.3.4" || o.Headers["X-Real-IP"] != "" {
		t.Fatalf("unexpected origin metadata: %+v", o)
	}
	// Environment proxy settings must not affect direct endpoint health checks.
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	if !c.Healthy(context.Background()) {
		t.Fatal("direct health used environment proxy")
	}
}

func TestOwnedRejectsReplayForgedSignatureAndWrongBody(t *testing.T) {
	s, _, c := ownedFixture(t)
	n := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	o := Observation{Version: 1, Nonce: n, Origin: "1.2.3.4", Method: "GET", SHA256: "bad"}
	b, _ := json.Marshal(s.signed(o))
	if _, err := c.verify(b, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"); err == nil {
		t.Fatal("accepted replay")
	}
	if err := o.VerifyBody("GET", nil); err == nil {
		t.Fatal("accepted wrong body digest")
	}
	other, err := New()
	if err != nil {
		t.Fatal(err)
	}
	b, _ = json.Marshal(other.signed(o))
	if _, err := c.verify(b, n); err == nil {
		t.Fatal("accepted different signing key")
	}
	e := s.signed(o)
	e.Payload[0] ^= 1
	b, _ = json.Marshal(e)
	if _, err := c.verify(b, n); err == nil {
		t.Fatal("accepted altered signed bytes")
	}
}

func TestOwnedRequiresTLSAndNeverFollowsRedirects(t *testing.T) {
	s, ts, c := ownedFixture(t)
	untrusted, err := NewClient(s.Descriptor(ts.URL), "", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = untrusted.Probe(context.Background(), "", time.Second, false); err == nil {
		t.Fatal("accepted untrusted TLS")
	}
	var followed bool
	redirect := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/trap" {
			followed = true
		}
		http.Redirect(w, r, "/trap", 302)
	}))
	defer redirect.Close()
	c.base = redirect.URL + s.path
	c.roots = redirect.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	if _, err = c.Probe(context.Background(), "", time.Second, false); err == nil || followed {
		t.Fatal("followed redirect")
	}
	for _, descriptor := range []string{strings.Replace(s.Descriptor(ts.URL), "https:", "http:", 1), ts.URL, ts.URL + "/test#bad", "https://user:pass@example.com/path#bad"} {
		if _, err := NewClient(descriptor, "", time.Second); err == nil {
			t.Fatalf("accepted %q", descriptor)
		}
	}
}

func TestEndpointBoundsAndMissingMetadata(t *testing.T) {
	s, _, c := ownedFixture(t)
	for _, tc := range []struct {
		body   string
		origin string
		nonce  string
		code   int
	}{{"", "", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 503}, {strings.Repeat("a", maxBody+1), "9.9.9.9", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 413}, {"", "9.9.9.9", "bad", 400}} {
		r := httptest.NewRequest("POST", s.path+"/probe?nonce="+tc.nonce, strings.NewReader(tc.body))
		r.Header.Set("X-Real-IP", tc.origin)
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if w.Code != tc.code {
			t.Fatalf("status %d, want %d", w.Code, tc.code)
		}
	}
	// Oversized signed envelopes are rejected before decoding their signature.
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, strings.Repeat("x", 33<<10)) }))
	defer ts.Close()
	c.base = ts.URL + s.path
	c.roots = ts.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	if _, err := c.Probe(context.Background(), "", time.Second, false); err == nil {
		t.Fatal("accepted oversized response")
	}
}

func TestProbeCancellationDuringProxyHandshake(t *testing.T) {
	_, _, c := ownedFixture(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = io.Copy(io.Discard, conn)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := c.Probe(ctx, "http://"+ln.Addr().String(), time.Second, false); err == nil {
		t.Fatal("stalled CONNECT succeeded")
	}
	if time.Since(start) > 500*time.Millisecond {
		t.Fatal("cancellation did not interrupt CONNECT")
	}
	<-done
}

func TestDescriptorKeyPinIsPublicOnly(t *testing.T) {
	s, _, _ := ownedFixture(t)
	fragment := strings.Split(s.Descriptor("https://example.test:12345"), "#")[1]
	key, err := base64.RawURLEncoding.DecodeString(fragment)
	if err != nil || len(key) != ed25519.PublicKeySize {
		t.Fatal("invalid public key descriptor")
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if ed25519.Verify(ed25519.PublicKey(key), []byte("x"), ed25519.Sign(private, []byte("x"))) {
		t.Fatal("unrelated signing key accepted")
	}
}

func TestDeepProbeCancellationDuringWebSocketRead(t *testing.T) {
	s, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ready := make(chan struct{})
	peerClosed := make(chan struct{})
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/ws") {
			u := websocket.Upgrader{}
			conn, err := u.Upgrade(w, r, nil)
			if err != nil {
				return
			}
			defer conn.Close()
			if _, _, err = conn.ReadMessage(); err != nil {
				return
			}
			close(ready)
			_, _, _ = conn.ReadMessage()
			close(peerClosed)
			return
		}
		r.Header.Set("X-Real-IP", "9.9.9.9")
		s.ServeHTTP(w, r)
	}))
	defer ts.Close()
	c, err := NewClient(s.Descriptor(ts.URL), "", 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	c.roots = ts.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := c.Probe(ctx, "", time.Second, true); done <- err }()
	select {
	case <-ready:
	case <-time.After(2 * time.Second):
		t.Fatal("WebSocket was not reached")
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled WebSocket probe succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("canceled WebSocket read hung")
	}
	select {
	case <-peerClosed:
	case <-time.After(time.Second):
		t.Fatal("cancellation left the upgraded connection open")
	}
}
