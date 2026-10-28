package checkservice

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

type XrokOptions struct {
	Binary         string
	Config         string
	CAFile         string
	StartupTimeout time.Duration
}

type Tunnel struct {
	Descriptor string
	CAFile     string
	done       chan struct{}
	closeOnce  sync.Once
	cancel     context.CancelFunc
	server     *http.Server
	service    *Service
	dir        string
	err        error
}

func (t *Tunnel) Done() <-chan struct{} { return t.done }
func (t *Tunnel) Err() error            { <-t.done; return t.err }
func (t *Tunnel) Close() {
	t.closeOnce.Do(func() { t.cancel(); _ = t.server.Close(); t.service.Close(); <-t.done; _ = os.RemoveAll(t.dir) })
}

// isolatedProfile preserves connection/authentication settings, but never starts
// unrelated forwards, reuses a fixed identity, or writes into the user's logs.
func isolatedProfile(path string) ([]byte, string, error) {
	if path == "" {
		path = os.Getenv("XROK_CONFIG")
	}
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, "", err
		}
		path = filepath.Join(home, ".xrok", "config.yaml")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, "", fmt.Errorf("read configured xrok profile: %w", err)
	}
	defer f.Close()
	b, err := readBounded(f, 1<<20)
	if err != nil {
		return nil, "", err
	}
	var profile map[string]any
	if err := yaml.Unmarshal(b, &profile); err != nil {
		return nil, "", fmt.Errorf("invalid xrok YAML profile")
	}
	if server, ok := profile["server"].(string); !ok || server == "" {
		return nil, "", fmt.Errorf("xrok profile requires server")
	}
	connection := make(map[string]any)
	for _, k := range []string{"version", "server", "server_port", "token", "tls", "transport", "connection_type", "headers", "compress", "reconnect", "http_proxy", "connect_timeout", "proxy_session", "proxy_session_header", "proxy_ca_cert", "client_cert", "client_key", "ca_cert", "insecure"} {
		if v, ok := profile[k]; ok {
			connection[k] = v
		}
	}
	profile = connection
	// P2P can change the data path and cause unrelated STUN/TURN traffic. This
	// service deliberately uses the existing server tunnel transport instead.
	delete(profile, "p2p")
	profile["quiet"] = false
	for _, k := range []string{"client_cert", "client_key", "ca_cert", "proxy_ca_cert"} {
		if s, ok := profile[k].(string); ok && s != "" {
			p, err := filepath.Abs(s)
			if err != nil {
				return nil, "", err
			}
			profile[k] = p
		}
	}
	ca, _ := profile["ca_cert"].(string)
	out, err := yaml.Marshal(profile)
	return out, ca, err
}

var ansi = regexp.MustCompile(`\x1b\[[0-?]*[ -/]*[@-~]`)

// xrok currently announces the server-assigned URL in its CLI output. Parse
// only our random tunnel's announcement and discard all other output, including
// debug/auth details. Never reconstruct an address from a configured domain.
type announcement struct {
	mu      sync.Mutex
	pending string
	name    string
	urls    chan string
}

func (a *announcement) Write(p []byte) (int, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.pending += string(p)
	for {
		line, rest, ok := strings.Cut(a.pending, "\n")
		if !ok {
			break
		}
		a.pending = rest
		f := strings.Fields(ansi.ReplaceAllString(line, ""))
		for i := 0; i+4 < len(f); i++ {
			if f[i] == "Tunnel" && f[i+1] == a.name && f[i+2] == "available" && f[i+3] == "at" {
				u, err := url.Parse(f[i+4])
				if err == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.RawQuery == "" && u.Fragment == "" && (u.Path == "" || u.Path == "/") {
					select {
					case a.urls <- u.String():
					default:
					}
				}
			}
		}
	}
	if len(a.pending) > 8192 {
		a.pending = ""
	}
	return len(p), nil
}

// StartXrok owns only its child process and an ephemeral loopback listener. It
// does not modify xrok, the source profile, server config, DNS, or public ports.
func StartXrok(ctx context.Context, opts XrokOptions) (*Tunnel, error) {
	profile, ca, err := isolatedProfile(opts.Config)
	if err != nil {
		return nil, err
	}
	if opts.CAFile != "" {
		ca = opts.CAFile
	}
	if ca != "" {
		ca, err = filepath.Abs(ca)
		if err != nil {
			return nil, err
		}
	}
	bin := opts.Binary
	if bin == "" {
		bin = "xrok"
	}
	bin, err = exec.LookPath(bin)
	if err != nil {
		return nil, fmt.Errorf("find installed xrok: %w", err)
	}
	bin, err = filepath.Abs(bin)
	if err != nil {
		return nil, err
	}
	s, err := New()
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp("", "proxymachine-check-xrok-")
	if err != nil {
		_ = ln.Close()
		return nil, err
	}
	if err = os.WriteFile(filepath.Join(dir, "client.yaml"), profile, 0600); err != nil {
		_ = ln.Close()
		_ = os.RemoveAll(dir)
		return nil, err
	}
	procCtx, cancel := context.WithCancel(ctx)
	t := &Tunnel{CAFile: ca, done: make(chan struct{}), cancel: cancel, service: s, dir: dir}
	t.server = &http.Server{Handler: s, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 10 * time.Second, MaxHeaderBytes: 16 << 10}
	name := "pmcheck-" + strings.TrimPrefix(s.path, "/")[:16]
	output := &announcement{name: name, urls: make(chan string, 1)}
	cmd := exec.CommandContext(procCtx, bin, "client", "--config", filepath.Join(dir, "client.yaml"), "--tunnel", name+":"+ln.Addr().String())
	cmd.Dir = dir
	cmd.Stdout = output
	cmd.Stderr = output
	cmd.WaitDelay = 3 * time.Second
	cmd.Cancel = func() error { return cmd.Process.Signal(os.Interrupt) }
	if err = cmd.Start(); err != nil {
		cancel()
		_ = ln.Close()
		_ = os.RemoveAll(dir)
		return nil, fmt.Errorf("start xrok: %w", err)
	}
	go func() {
		t.err = cmd.Wait()
		if t.err == nil {
			t.err = fmt.Errorf("xrok exited")
		}
		close(t.done)
	}()
	go func() {
		if err := t.server.Serve(ln); err != nil && err != http.ErrServerClosed {
			cancel()
		}
	}()
	wait := opts.StartupTimeout
	if wait <= 0 {
		wait = 60 * time.Second
	}
	startup, stop := context.WithTimeout(ctx, wait)
	defer stop()
	var base string
	select {
	case base = <-output.urls:
	case <-t.done:
		t.Close()
		return nil, fmt.Errorf("xrok exited before announcing a tunnel URL: %w", t.Err())
	case <-startup.Done():
		t.Close()
		return nil, fmt.Errorf("waiting for xrok tunnel announcement: %w", startup.Err())
	}
	t.Descriptor = s.Descriptor(base)
	c, err := NewClient(t.Descriptor, ca, 5*time.Second)
	if err != nil {
		t.Close()
		return nil, err
	}
	for {
		if _, err = c.Probe(startup, "", 0, false); err == nil {
			go func() {
				for {
					select {
					case <-procCtx.Done():
						return
					case next := <-output.urls:
						if next != base {
							cancel()
							return
						}
					}
				}
			}()
			return t, nil
		}
		timer := time.NewTimer(200 * time.Millisecond)
		select {
		case <-startup.Done():
			timer.Stop()
			t.Close()
			return nil, fmt.Errorf("xrok check service did not become ready (TLS, signing key and origin metadata required): %w", startup.Err())
		case <-t.done:
			timer.Stop()
			t.Close()
			return nil, fmt.Errorf("xrok exited during readiness check: %w", t.Err())
		case <-timer.C:
		}
	}
}
