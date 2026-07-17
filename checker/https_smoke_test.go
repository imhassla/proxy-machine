package checker

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"proxymachine/config"
)

// connectHandler tunnels a CONNECT request straight to its target (a stand-in upstream
// proxy). Shared by the TLS ("real https proxy") and plaintext ("mislabeled https") fakes.
func connectHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		http.Error(w, "only CONNECT", http.StatusMethodNotAllowed)
		return
	}
	up, err := net.Dial("tcp", r.Host)
	if err != nil {
		http.Error(w, "dial", http.StatusBadGateway)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "no hijack", http.StatusInternalServerError)
		return
	}
	conn, _, err := hj.Hijack()
	if err != nil {
		up.Close()
		return
	}
	io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
	go func() { io.Copy(up, conn); up.Close() }()
	io.Copy(conn, up)
	conn.Close()
}

// TestHTTPSProxyValidation is a smoke test for the "why is /proxy/https empty?" question.
// It proves the two halves of the answer deterministically (no network):
//
//  1. A REAL https proxy (TLS-to-proxy that speaks CONNECT) DOES validate under type=https.
//     → the code path is correct.
//  2. A PLAINTEXT http proxy (which is what public "https proxy" lists actually contain —
//     CONNECT-capable http proxies you connect to in the clear) FAILS under type=https,
//     because we TLS-handshake the proxy hop and there's no TLS server there.
//     → this is why the https table stays ~empty: the data isn't really TLS proxies.
func TestHTTPSProxyValidation(t *testing.T) {
	// The proxy-test target must be https so the transport CONNECT-tunnels through the proxy.
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"origin":"9.9.9.9"}`) // != our self-IP → "alive + anonymous"
	}))
	defer origin.Close()

	cm := New(&config.Config{Workers: 1, Timeout: 5 * time.Second, ConnectTimeout: 3 * time.Second}, nil)
	cm.TestURLs = []string{origin.URL}
	const selfIP = "1.2.3.4"

	// (1) Real https proxy: TLS listener that handles CONNECT. Force http/1.1 so Hijack works.
	tlsProxy := httptest.NewUnstartedServer(http.HandlerFunc(connectHandler))
	tlsProxy.TLS = &tls.Config{NextProtos: []string{"http/1.1"}}
	tlsProxy.StartTLS()
	defer tlsProxy.Close()
	tlsAddr := strings.TrimPrefix(tlsProxy.URL, "https://")

	rt, ok := cm.check(context.Background(), selfIP, proxyJob{addr: tlsAddr, typ: "https"})
	if !ok {
		t.Fatalf("a real https (TLS-to-proxy) proxy should validate under type=https, but it FAILED — the https code path is broken")
	}
	t.Logf("OK: real https proxy validated (rt=%.3fs) — code path correct", rt)

	// (2) Plaintext http proxy mislabeled as https: dialing it as https:// TLS-handshakes a
	// plaintext server → must fail. This is what real public "https" lists contain.
	plainProxy := httptest.NewServer(http.HandlerFunc(connectHandler))
	defer plainProxy.Close()
	plainAddr := strings.TrimPrefix(plainProxy.URL, "http://")

	if _, ok := cm.check(context.Background(), selfIP, proxyJob{addr: plainAddr, typ: "https"}); ok {
		t.Fatalf("a plaintext http proxy must NOT validate as https (no TLS server on the proxy hop)")
	}
	t.Logf("OK: plaintext proxy correctly REJECTED as https — this is why public 'https' lists (which are plaintext CONNECT proxies) leave /proxy/https empty. Those entries are really http proxies, and http proxies already tunnel HTTPS via CONNECT (the relay does this).")
}
