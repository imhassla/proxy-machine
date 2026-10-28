package checkservice

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// This child implements xrok's existing announcement contract, not its tunnel
// protocol. The real binary is exercised separately in the controlled lab.
func TestXrokHelperProcess(t *testing.T) {
	if os.Getenv("PM_XROK_HELPER") != "1" {
		return
	}
	if os.Getenv("PM_XROK_MODE") == "exit" {
		os.Exit(7)
	}
	args := os.Args
	var target, profile string
	for i := 0; i+1 < len(args); i++ {
		switch args[i] {
		case "--tunnel":
			target = args[i+1]
		case "--config":
			profile = args[i+1]
		}
	}
	b, err := os.ReadFile(profile)
	if err != nil {
		os.Exit(8)
	}
	stat, err := os.Stat(profile)
	if err != nil || stat.Mode().Perm() != 0600 {
		os.Exit(9)
	}
	if err = os.WriteFile(os.Getenv("PM_XROK_CAPTURE"), b, 0600); err != nil {
		os.Exit(10)
	}
	if err = os.WriteFile(os.Getenv("PM_XROK_TARGET"), []byte(strings.SplitN(target, ":", 2)[1]), 0600); err != nil {
		os.Exit(11)
	}
	if os.Getenv("PM_XROK_MODE") != "silent" {
		fmt.Printf("\x1b[36m→ Tunnel \x1b[1m%s\x1b[0m available at \x1b[1m%s\x1b[0m\n", strings.SplitN(target, ":", 2)[0], os.Getenv("PM_XROK_URL"))
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	<-ctx.Done()
	os.Exit(0)
}

func fakeXrok(t *testing.T) (XrokOptions, string, string) {
	t.Helper()
	dir := t.TempDir()
	capture := filepath.Join(dir, "capture.yaml")
	target := filepath.Join(dir, "target")
	profile := filepath.Join(dir, "user.yaml")
	original := []byte("server: configured.example\nserver_port: 54321\ntoken: keep-private\nquiet: true\nid: existing-client\ntunnels: [{name: existing, target: 'localhost:80'}]\nreverse: [{remote: ':9017', local: 'localhost:80'}]\nsocks5: ':1080'\nudp: [{local: ':5353', remote: 'localhost:53'}]\np2p: {enabled: true}\nlog_file: existing.log\n")
	if err := os.WriteFile(profile, original, 0600); err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: time.Second}
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := os.ReadFile(target)
		if err != nil {
			http.Error(w, "waiting", 503)
			return
		}
		req, err := http.NewRequestWithContext(r.Context(), r.Method, "http://"+string(b)+r.URL.RequestURI(), r.Body)
		if err != nil {
			http.Error(w, "bad request", 500)
			return
		}
		req.Header = r.Header.Clone()
		req.Header.Set("X-Real-IP", "1.2.3.4")
		req.Header.Set("X-Forwarded-For", "1.2.3.4")
		resp, err := client.Do(req)
		if err != nil {
			http.Error(w, "offline", 503)
			return
		}
		defer resp.Body.Close()
		for k, v := range resp.Header {
			w.Header()[k] = v
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	}))
	t.Cleanup(ts.Close)
	cert, err := x509.ParseCertificate(ts.TLS.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	ca := filepath.Join(dir, "ca.pem")
	if err = os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "xrok")
	script := "#!/bin/sh\nexec '" + strings.ReplaceAll(exe, "'", "'\"'\"'") + "' -test.run=TestXrokHelperProcess -- \"$@\"\n"
	if err = os.WriteFile(bin, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	for k, v := range map[string]string{"PM_XROK_HELPER": "1", "PM_XROK_CAPTURE": capture, "PM_XROK_TARGET": target, "PM_XROK_URL": ts.URL} {
		t.Setenv(k, v)
	}
	// Full race suites may contend for process startup CPU; cancellation has
	// its own short explicit deadline below and must not depend on this budget.
	return XrokOptions{Binary: bin, Config: profile, CAFile: ca, StartupTimeout: 10 * time.Second}, capture, target
}

func TestManagedXrokUsesAssignedURLAndIsolatedProfile(t *testing.T) {
	opts, capture, target := fakeXrok(t)
	before, err := os.ReadFile(opts.Config)
	if err != nil {
		t.Fatal(err)
	}
	tunnel, err := StartXrok(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	defer tunnel.Close()
	if !strings.HasPrefix(tunnel.Descriptor, os.Getenv("PM_XROK_URL")+"/") {
		t.Fatalf("did not use announced URL: %s", tunnel.Descriptor)
	}
	b, err := os.ReadFile(capture)
	if err != nil {
		t.Fatal(err)
	}
	var profile map[string]any
	if err = yaml.Unmarshal(b, &profile); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"id", "reverse", "socks5", "tunnels", "udp", "p2p", "log_file"} {
		if _, ok := profile[k]; ok {
			t.Fatalf("inherited unrelated profile field %s", k)
		}
	}
	if profile["token"] != "keep-private" || profile["server_port"] != 54321 || profile["quiet"] != false {
		t.Fatalf("connection settings or output mode lost")
	}
	after, _ := os.ReadFile(opts.Config)
	if string(before) != string(after) {
		t.Fatal("modified source profile")
	}
	address, _ := os.ReadFile(target)
	tunnel.Close()
	if _, err := os.Stat(tunnel.dir); !os.IsNotExist(err) {
		t.Fatal("temporary profile retained after close")
	}
	conn, err := net.DialTimeout("tcp", string(address), 100*time.Millisecond)
	if err == nil {
		conn.Close()
		t.Fatal("local endpoint still listening")
	}
}

func TestManagedXrokEarlyExitAndStartupCancellation(t *testing.T) {
	for _, mode := range []string{"exit", "silent"} {
		t.Run(mode, func(t *testing.T) {
			opts, _, _ := fakeXrok(t)
			t.Setenv("PM_XROK_MODE", mode)
			opts.StartupTimeout = 150 * time.Millisecond
			start := time.Now()
			if tunnel, err := StartXrok(context.Background(), opts); err == nil {
				tunnel.Close()
				t.Fatal("unexpected ready service")
			}
			if time.Since(start) > 4*time.Second {
				t.Fatal("startup cancellation hung")
			}
		})
	}
}

func TestAnnouncementRejectsOtherTunnelAndInvalidURLs(t *testing.T) {
	a := announcement{name: "owned", urls: make(chan string, 1)}
	for _, line := range []string{"Tunnel other available at https://evil.test\n", "Tunnel owned available at http://plain.test\n", "Tunnel owned available at https://user:secret@evil.test\n", "Tunnel owned available at https://ok.test/?token=secret\n"} {
		_, _ = a.Write([]byte(line))
	}
	select {
	case <-a.urls:
		t.Fatal("accepted unrelated or unsafe URL")
	default:
	}
	for _, part := range []string{"\x1b[36m→ Tunnel ow", "ned available at https://assigned.test:44444\x1b[0m\n"} {
		_, _ = a.Write([]byte(part))
	}
	select {
	case got := <-a.urls:
		if got != "https://assigned.test:44444" {
			t.Fatal(got)
		}
	default:
		t.Fatal("missed split announcement")
	}
	_, _ = a.Write([]byte(strings.Repeat("x", 9000)))
	if len(a.pending) > 8192 {
		t.Fatal("unbounded output buffer")
	}
}

func TestProfilePathDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "client.yaml")
	if err := os.WriteFile(path, []byte("server: example.test\nserver_port: 12345\ntoken: secret\nca_cert: relative.pem\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XROK_CONFIG", path)
	b, ca, err := isolatedProfile("")
	if err != nil {
		t.Fatal(err)
	}
	var p map[string]any
	if err = yaml.Unmarshal(b, &p); err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(ca) || p["token"] != "secret" {
		t.Fatal("profile environment/relative certificate path lost")
	}
	// Descriptors carry only the public verification key, never profile tokens.
	s, _ := New()
	d := s.Descriptor("https://example.test:12345")
	encoded, _ := json.Marshal(d)
	if strings.Contains(string(encoded), "secret") {
		t.Fatal("profile token in descriptor")
	}
}
