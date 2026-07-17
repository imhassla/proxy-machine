// Package config provides application configuration loaded from defaults,
// JSON/INI files, and command-line flags. Flags override file values,
// which override defaults.
package config

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Config holds the application settings.
type Config struct {
	Workers int
	Timeout time.Duration
	// ConnectTimeout bounds just the TCP connect (+ SOCKS handshake) to a candidate proxy,
	// separately from Timeout (the whole per-proxy validation). A short connect timeout lets
	// dead proxies fail fast so a sweep converges, while a slow-but-alive proxy still gets
	// the full Timeout to answer.
	ConnectTimeout time.Duration
	DBPath         string

	// CheckInterval is the cadence of the background re-validation loop (re-check
	// stored proxies, validate fresh scan results / public lists, prune dead).
	CheckInterval time.Duration

	// RelayAddr / APIAddr / SocksAddr are the listen addresses. Default to LOOPBACK so a
	// fresh install is not an open proxy / open API exposed to the network. SocksAddr is
	// the client-facing SOCKS5 listener (empty → disabled).
	RelayAddr string
	APIAddr   string
	SocksAddr string

	// MaxFailover caps how many upstream proxies a single relayed request/tunnel will try
	// before giving up (bounds the round-robin walk over a DB full of dead proxies).
	MaxFailover int

	// StickyHeader, when set, enables session affinity: relay requests carrying this header
	// are pinned to the upstream they last succeeded through (empty → sticky disabled).
	// StickyTTL is the sliding idle lifetime of a pin.
	StickyHeader string
	StickyTTL    time.Duration

	// ProxyUser / ProxyPass, when ProxyUser is non-empty, require HTTP Basic
	// Proxy-Authorization on every relay request. Empty → no auth (safe only with the
	// loopback default bind; a non-loopback RelayAddr should always set credentials).
	ProxyUser string
	ProxyPass string
}

// Load parses command-line flags and optional config file to produce Config.
// args should typically be os.Args[1:].
func Load(args []string) (*Config, error) {
	cfg := &Config{
		Workers:        50,
		Timeout:        30 * time.Second,
		ConnectTimeout: 5 * time.Second,
		DBPath:         "data.db",
		CheckInterval:  60 * time.Second,
		RelayAddr:      "127.0.0.1:3333",
		APIAddr:        "127.0.0.1:8000",
		SocksAddr:      "127.0.0.1:1080",
		MaxFailover:    5,
		StickyTTL:      10 * time.Minute,
	}

	var configPath string
	var workers, maxFailover int
	var timeout, checkInterval, stickyTTL, connectTimeout time.Duration
	var dbPath, relayAddr, apiAddr, socksAddr, proxyUser, proxyPass, stickyHeader string

	fs := flag.NewFlagSet("config", flag.ContinueOnError)
	fs.StringVar(&configPath, "config", "", "Path to JSON or INI config file")
	fs.IntVar(&workers, "workers", -1, "Number of workers")
	fs.DurationVar(&timeout, "timeout", -1, "Timeout duration")
	fs.DurationVar(&connectTimeout, "connectTimeout", -1, "Per-proxy connect timeout (default 5s)")
	fs.DurationVar(&checkInterval, "checkInterval", -1, "Background re-check interval")
	fs.StringVar(&dbPath, "dbPath", "", "Path to database file")
	fs.StringVar(&relayAddr, "relayAddr", "", "HTTP relay listen address (default 127.0.0.1:3333)")
	fs.StringVar(&apiAddr, "apiAddr", "", "API listen address (default 127.0.0.1:8000)")
	fs.StringVar(&socksAddr, "socksAddr", "", "Client SOCKS5 listen address (default 127.0.0.1:1080; 'off' to disable)")
	fs.IntVar(&maxFailover, "maxFailover", -1, "Max upstream proxies tried per request (default 5)")
	fs.StringVar(&stickyHeader, "stickyHeader", "", "Request header for session affinity (empty = off)")
	fs.DurationVar(&stickyTTL, "stickyTTL", -1, "Sliding TTL of a sticky-session pin (default 10m)")
	fs.StringVar(&proxyUser, "proxyUser", "", "Relay/SOCKS auth username (enables auth when set)")
	fs.StringVar(&proxyPass, "proxyPass", "", "Relay/SOCKS auth password")

	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	if configPath != "" {
		if err := loadFile(configPath, cfg); err != nil {
			return nil, err
		}
	}

	if workers >= 0 {
		cfg.Workers = workers
	}
	if timeout >= 0 {
		cfg.Timeout = timeout
	}
	if connectTimeout >= 0 {
		cfg.ConnectTimeout = connectTimeout
	}
	if checkInterval >= 0 {
		cfg.CheckInterval = checkInterval
	}
	if dbPath != "" {
		cfg.DBPath = dbPath
	}
	if relayAddr != "" {
		cfg.RelayAddr = relayAddr
	}
	if apiAddr != "" {
		cfg.APIAddr = apiAddr
	}
	if socksAddr != "" {
		if socksAddr == "off" || socksAddr == "none" {
			cfg.SocksAddr = ""
		} else {
			cfg.SocksAddr = socksAddr
		}
	}
	if maxFailover >= 0 {
		cfg.MaxFailover = maxFailover
	}
	if stickyHeader != "" {
		cfg.StickyHeader = stickyHeader
	}
	if stickyTTL >= 0 {
		cfg.StickyTTL = stickyTTL
	}
	if proxyUser != "" {
		cfg.ProxyUser = proxyUser
	}
	if proxyPass != "" {
		cfg.ProxyPass = proxyPass
	}

	return cfg, nil
}

func loadFile(path string, cfg *Config) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".json":
		return loadJSON(data, cfg)
	case ".ini", ".conf", ".cfg", "":
		return loadINI(data, cfg)
	default:
		return fmt.Errorf("unsupported config file format: %s", ext)
	}
}

type fileConfig struct {
	Workers        *int    `json:"workers"`
	Timeout        *string `json:"timeout"`
	ConnectTimeout *string `json:"connectTimeout"`
	DBPath         *string `json:"dbPath"`
	CheckInterval  *string `json:"checkInterval"`
	RelayAddr      *string `json:"relayAddr"`
	APIAddr        *string `json:"apiAddr"`
	SocksAddr      *string `json:"socksAddr"`
	MaxFailover    *int    `json:"maxFailover"`
	StickyHeader   *string `json:"stickyHeader"`
	StickyTTL      *string `json:"stickyTTL"`
	ProxyUser      *string `json:"proxyUser"`
	ProxyPass      *string `json:"proxyPass"`
}

func loadJSON(data []byte, cfg *Config) error {
	var fc fileConfig
	if err := json.Unmarshal(data, &fc); err != nil {
		return err
	}
	return applyFileConfig(fc, cfg)
}

func loadINI(data []byte, cfg *Config) error {
	var fc fileConfig
	section := ""
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		val = strings.TrimSpace(val)
		val = strings.Trim(val, `"'`)

		// Section-qualified key: an INI [database] path = ... section.
		if section == "database" && key == "path" && fc.DBPath == nil {
			fc.DBPath = &val
			continue
		}

		switch key {
		case "workers":
			v, err := strconv.Atoi(val)
			if err != nil {
				return fmt.Errorf("invalid workers value %q: %w", val, err)
			}
			if fc.Workers == nil {
				w := v
				fc.Workers = &w
			}
		case "timeout":
			if fc.Timeout == nil {
				fc.Timeout = &val
			}
		case "connecttimeout":
			if fc.ConnectTimeout == nil {
				fc.ConnectTimeout = &val
			}
		case "dbpath", "db.path":
			if fc.DBPath == nil {
				fc.DBPath = &val
			}
		case "checkinterval":
			if fc.CheckInterval == nil {
				fc.CheckInterval = &val
			}
		case "relayaddr":
			if fc.RelayAddr == nil {
				fc.RelayAddr = &val
			}
		case "apiaddr":
			if fc.APIAddr == nil {
				fc.APIAddr = &val
			}
		case "socksaddr":
			if fc.SocksAddr == nil {
				fc.SocksAddr = &val
			}
		case "maxfailover":
			v, err := strconv.Atoi(val)
			if err != nil {
				return fmt.Errorf("invalid maxFailover value %q: %w", val, err)
			}
			if fc.MaxFailover == nil {
				fc.MaxFailover = &v
			}
		case "stickyheader":
			if fc.StickyHeader == nil {
				fc.StickyHeader = &val
			}
		case "stickyttl":
			if fc.StickyTTL == nil {
				fc.StickyTTL = &val
			}
		case "proxyuser":
			if fc.ProxyUser == nil {
				fc.ProxyUser = &val
			}
		case "proxypass":
			if fc.ProxyPass == nil {
				fc.ProxyPass = &val
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return applyFileConfig(fc, cfg)
}

func applyFileConfig(fc fileConfig, cfg *Config) error {
	if fc.Workers != nil {
		if *fc.Workers < 0 {
			return fmt.Errorf("workers must be non-negative")
		}
		cfg.Workers = *fc.Workers
	}
	if fc.Timeout != nil {
		d, err := time.ParseDuration(*fc.Timeout)
		if err != nil {
			return fmt.Errorf("invalid timeout value %q: %w", *fc.Timeout, err)
		}
		cfg.Timeout = d
	}
	if fc.ConnectTimeout != nil {
		d, err := time.ParseDuration(*fc.ConnectTimeout)
		if err != nil {
			return fmt.Errorf("invalid connectTimeout value %q: %w", *fc.ConnectTimeout, err)
		}
		cfg.ConnectTimeout = d
	}
	if fc.DBPath != nil {
		cfg.DBPath = *fc.DBPath
	}
	if fc.CheckInterval != nil {
		d, err := time.ParseDuration(*fc.CheckInterval)
		if err != nil {
			return fmt.Errorf("invalid checkInterval value %q: %w", *fc.CheckInterval, err)
		}
		cfg.CheckInterval = d
	}
	if fc.RelayAddr != nil {
		cfg.RelayAddr = *fc.RelayAddr
	}
	if fc.APIAddr != nil {
		cfg.APIAddr = *fc.APIAddr
	}
	if fc.SocksAddr != nil {
		// Same off/none → "" (disabled) normalization the CLI flag gets, so disabling the
		// SOCKS listener via a config file doesn't become net.Listen("tcp","off") at startup.
		if *fc.SocksAddr == "off" || *fc.SocksAddr == "none" {
			cfg.SocksAddr = ""
		} else {
			cfg.SocksAddr = *fc.SocksAddr
		}
	}
	if fc.MaxFailover != nil {
		if *fc.MaxFailover < 0 {
			return fmt.Errorf("maxFailover must be non-negative")
		}
		cfg.MaxFailover = *fc.MaxFailover
	}
	if fc.StickyHeader != nil {
		cfg.StickyHeader = *fc.StickyHeader
	}
	if fc.StickyTTL != nil {
		d, err := time.ParseDuration(*fc.StickyTTL)
		if err != nil {
			return fmt.Errorf("invalid stickyTTL value %q: %w", *fc.StickyTTL, err)
		}
		cfg.StickyTTL = d
	}
	if fc.ProxyUser != nil {
		cfg.ProxyUser = *fc.ProxyUser
	}
	if fc.ProxyPass != nil {
		cfg.ProxyPass = *fc.ProxyPass
	}
	return nil
}
