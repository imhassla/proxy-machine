package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"proxymachine/api"
	"proxymachine/checker"
	"proxymachine/config"
	"proxymachine/db"
	"proxymachine/metrics"
	"proxymachine/pkg/geo"
	"proxymachine/pkg/relay"
	"proxymachine/pkg/scanner"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "scan" {
		if err := runScanner(os.Args[2:]); err != nil {
			log.Fatalf("scan: %v", err)
		}
		return
	}

	if len(os.Args) > 1 && os.Args[1] == "discover" {
		if err := runDiscover(os.Args[2:]); err != nil {
			log.Fatalf("discover: %v", err)
		}
		return
	}

	if len(os.Args) > 1 && os.Args[1] == "validate" {
		if err := runValidate(os.Args[2:]); err != nil {
			log.Fatalf("validate: %v", err)
		}
		return
	}

	if err := runService(os.Args[1:]); err != nil {
		log.Fatalf("service: %v", err)
	}
}

func runService(args []string) error {
	cfg, err := config.Load(args)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	database, err := db.Open(cfg.DBPath)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	if err := database.Init(); err != nil {
		_ = database.Close()
		return fmt.Errorf("init database: %w", err)
	}

	manager := checker.New(cfg, database)
	if len(cfg.Sources) > 0 {
		manager.ListURLs = cfg.Sources
		log.Printf("checker: using %d configured proxy sources (overriding built-in list)", len(cfg.Sources))
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	met := metrics.New()
	server := api.New(cfg.APIAddr, manager, database, met)
	relayServer := relay.New(cfg, manager, database, met)
	// Expose the relay's live upstream health via GET /upstreams.
	server.SetUpstreamsProvider(func() any { return relayServer.Upstreams() })
	server.SetRelayAddr(cfg.RelayAddr) // advertised first in /proxy.pac
	server.SetDiscoverEnabled(cfg.Discover)

	// Geo/ASN enrichment runs as its OWN background process (online lookup), independent of
	// the checker so validation never waits on it. Errors are logged internally. The enricher
	// stays silent; the checker folds its progress (GeoResolved) into the cycle-done line.
	// Wire GeoResolved BEFORE starting the checker so there's no data race on the field.
	var geoEnricher *geo.Enricher
	if cfg.GeoLookup {
		geoEnricher = geo.New(database)
		manager.GeoResolved = geoEnricher.Resolved
	}

	var checkerErr error
	checkerDone := make(chan struct{})
	go func() {
		defer close(checkerDone)
		checkerErr = manager.Start(ctx)
	}()

	geoDone := make(chan struct{})
	go func() {
		defer close(geoDone)
		if geoEnricher != nil {
			_ = geoEnricher.Run(ctx)
		}
	}()

	// Optional neighbor-discovery job: periodically expand the pool by port-scanning the /24
	// neighbors of known proxies (on their recurring ports) THROUGH the validated pool
	// (socks5/socks4/http egress), feeding open ip:ports to the checker. Off unless --discover.
	discoverDone := make(chan struct{})
	go func() {
		defer close(discoverDone)
		if !cfg.Discover {
			return
		}
		mode := cfg.DiscoverInterval.String()
		if cfg.DiscoverInterval <= 0 {
			mode = "continuous (pass after pass)"
		}
		log.Printf("discovery job enabled: scanning known-proxy neighbors %s (minDensity=%d)", mode, cfg.DiscoverMinDensity)
		sc := scanner.New(database)
		timer := time.NewTimer(2 * time.Minute) // let the checker populate the pool first
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
			}
			// A pass runs to completion (never interrupted by the interval); the interval is the
			// gap AFTER it finishes before the next pass. DiscoverInterval<=0 means loop pass
			// after pass with only a small floor so an empty/instant pass can't hot-spin.
			if err := runDiscoverPass(ctx, manager, sc, cfg); err != nil && ctx.Err() == nil {
				log.Printf("discover: %v", err)
			}
			gap := cfg.DiscoverInterval
			if gap <= 0 {
				gap = 10 * time.Second
			}
			timer.Reset(gap)
		}
	}()

	// A server's Start() returns only on Shutdown (ErrServerClosed) or a fatal listen
	// error (e.g. address in use). Surface the fatal case on startErr so the service
	// fails fast instead of running degraded forever with a dead listener.
	startErr := make(chan error, 3)
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		log.Printf("api server listening on http://%s (docs at /, proxies at /proxy/{type})", cfg.APIAddr)
		if err := server.Start(); err != nil && err != http.ErrServerClosed {
			startErr <- fmt.Errorf("api server: %w", err)
		}
	}()

	relayDone := make(chan struct{})
	go func() {
		defer close(relayDone)
		log.Printf("relay server (HTTP + CONNECT) listening on %s", cfg.RelayAddr)
		if err := relayServer.Start(); err != nil && err != http.ErrServerClosed {
			startErr <- fmt.Errorf("relay server: %w", err)
		}
	}()

	// Optional client-facing SOCKS5 listener (nil when SocksAddr is empty/off).
	socksServer := relayServer.Socks()
	socksDone := make(chan struct{})
	go func() {
		defer close(socksDone)
		if socksServer == nil {
			return
		}
		log.Printf("socks5 server listening on %s", cfg.SocksAddr)
		if err := socksServer.Start(); err != nil {
			startErr <- fmt.Errorf("socks server: %w", err)
		}
	}()

	var fatal error
	select {
	case <-ctx.Done(): // SIGINT/SIGTERM — normal shutdown
	case fatal = <-startErr: // a listener died — shut everything down and exit non-zero
		log.Printf("fatal: %v", fatal)
		stop()
	}

	// Each server gets its OWN 5s shutdown budget — a slow API drain must not eat into
	// the relay's (they previously shared one deadline).
	stopWithin := func(name string, stop func(context.Context) error) {
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := stop(sctx); err != nil {
			log.Printf("stop %s: %v", name, err)
		}
	}
	stopWithin("api server", server.Stop)
	stopWithin("relay server", relayServer.Stop)
	if socksServer != nil {
		stopWithin("socks server", socksServer.Stop)
	}

	<-serverDone
	<-relayDone
	<-socksDone
	<-checkerDone
	<-geoDone
	<-discoverDone

	if err := database.Close(); err != nil {
		log.Printf("close database: %v", err)
	}

	if fatal != nil {
		return fatal
	}
	if checkerErr != nil && checkerErr != context.Canceled {
		return fmt.Errorf("checker: %w", checkerErr)
	}
	return nil
}

func runScanner(args []string) error {
	opts, err := scanner.LoadOptions(args)
	if err != nil {
		return err
	}

	database, err := db.Open(opts.DBPath)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	// Init the per-type tables before scanning. Without this a fresh DB file has no
	// socks4 table, so the scanner's socks4 lookup (for anonymous egress, with a
	// direct-probe fallback when empty) errors out instead of bootstrapping — the
	// scanner could never run standalone on a clean install.
	if err := database.Init(); err != nil {
		_ = database.Close()
		return fmt.Errorf("init database: %w", err)
	}
	defer func() {
		if err := database.Close(); err != nil {
			log.Printf("close database: %v", err)
		}
	}()

	s := scanner.New(database)
	return s.Scan(context.Background(), opts)
}

// runDiscover performs ONE neighbor-discovery pass: derive /24 neighbors of the proxies
// already in the DB and port-scan them through the validated pool (socks5/socks4/http egress),
// queuing open ip:ports to _scan_results for the checker to validate. Use it as a one-shot
// against a running instance's DB (the live checker picks up the results), or enable the
// continuous background job with --discover on the service. Flags: --dbPath, --workers,
// --connectTimeout, --discoverMinDensity.
func runDiscover(args []string) error {
	cfg, err := config.Load(args)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	database, err := db.Open(cfg.DBPath)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	if err := database.Init(); err != nil {
		_ = database.Close()
		return fmt.Errorf("init database: %w", err)
	}
	defer func() {
		if err := database.Close(); err != nil {
			log.Printf("close database: %v", err)
		}
	}()

	manager := checker.New(cfg, database)
	if err := runDiscoverPass(context.Background(), manager, scanner.New(database), cfg); err != nil {
		return err
	}
	return nil
}

// runValidate reads "ip:port" candidates from stdin (one per line), validates each as every
// proxy type, stores survivors, and attributes net-new ones — reusing the discovery streaming
// path. A general instrument for measuring the yield of ANY candidate-generation strategy:
// generate a list, pipe it in, read the "stored Y (Z net-new)" summary. Flags: --dbPath.
func runValidate(args []string) error {
	cfg, err := config.Load(args)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	database, err := db.Open(cfg.DBPath)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	if err := database.Init(); err != nil {
		_ = database.Close()
		return fmt.Errorf("init database: %w", err)
	}
	defer func() { _ = database.Close() }()

	ch := make(chan string, 256)
	go func() {
		defer close(ch)
		sc := bufio.NewScanner(os.Stdin)
		sc.Buffer(make([]byte, 64*1024), 1<<20)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line != "" {
				ch <- line
			}
		}
	}()

	stored, _, err := checker.New(cfg, database).ValidateAndStoreStream(context.Background(), ch)
	if err != nil {
		return err
	}
	log.Printf("validate: done — %d proxies stored (see the net-new count in the summary above)", stored)
	return nil
}

// runDiscoverPass runs one discovery pass with STREAMING validation. It feeds candidates into
// the checker, which validates each as every proxy type and stores survivors immediately (no
// cycle wait). Candidates come from the high-yield VALIDATE-ONLY strategies — sequential-IP,
// port-window, and common-port expansion of a sampled slice of the known pool — plus, only when
// --discoverScan is set, the expensive (low-yield) /24 neighbor port-scan. Shared by the
// --discover background job and the `discover` subcommand.
func runDiscoverPass(ctx context.Context, manager *checker.CheckManager, sc *scanner.Scanner, cfg *config.Config) error {
	// validate streams a candidate slice through the checker and returns (stored, net-new addrs).
	validate := func(cands []string) (int, []string, error) {
		ch := make(chan string, 256)
		go func() {
			defer close(ch)
			for _, c := range cands {
				select {
				case ch <- c:
				case <-ctx.Done():
					return
				}
			}
		}()
		return manager.ValidateAndStoreStream(ctx, ch)
	}

	// Round 0: validate-only expansion of a sampled slice of the pool (cheap, high-yield).
	cands, cerr := sc.ExpansionCandidates(cfg.DiscoverExpandSample, cfg.DiscoverSeqSpan, cfg.DiscoverPortWindow)
	if cerr != nil {
		return cerr
	}
	tried := make(map[string]struct{}, len(cands))
	for _, c := range cands {
		tried[c] = struct{}{}
	}
	log.Printf("discover: %d expansion candidates (sample=%d hosts, seq±%d, port±%d)",
		len(cands), cfg.DiscoverExpandSample, cfg.DiscoverSeqSpan, cfg.DiscoverPortWindow)
	totalStored, hits, err := validate(cands)
	if err != nil {
		return err
	}

	// Adaptive rounds: widen aggressively around each freshly-found proxy to grab the rest of
	// its block (contiguous ports / IPs), until a round finds nothing new.
	const adaptivePortWindow, adaptiveSeqSpan = 30, 8
	for round := 1; round <= cfg.DiscoverAdaptiveRounds && len(hits) > 0 && ctx.Err() == nil; round++ {
		var next []string
		for _, hp := range hits {
			for _, c := range scanner.AdaptiveCandidates(hp, adaptivePortWindow, adaptiveSeqSpan) {
				if _, ok := tried[c]; !ok {
					tried[c] = struct{}{}
					next = append(next, c)
				}
			}
		}
		if len(next) == 0 {
			break
		}
		log.Printf("discover: adaptive round %d — widening around %d fresh hits → %d candidates", round, len(hits), len(next))
		var s int
		s, hits, err = validate(next)
		if err != nil {
			return err
		}
		totalStored += s
	}

	// Gap-fill: sweep the full port range of the densest port-farm hosts to catch proxies in
	// the gaps between clusters that adaptive expansion's bounded window can't bridge.
	if cfg.DiscoverGapFill {
		const gapFillMinPorts, gapFillMaxSpan = 15, 2500
		gaps, gerr := sc.GapFillCandidates(gapFillMinPorts, cfg.DiscoverGapFillHosts, gapFillMaxSpan)
		if gerr == nil && len(gaps) > 0 {
			var fresh []string
			for _, c := range gaps {
				if _, ok := tried[c]; !ok {
					tried[c] = struct{}{}
					fresh = append(fresh, c)
				}
			}
			if len(fresh) > 0 {
				log.Printf("discover: gap-fill — sweeping %d ports across top %d port-farm hosts", len(fresh), cfg.DiscoverGapFillHosts)
				s, _, verr := validate(fresh)
				if verr != nil {
					return verr
				}
				totalStored += s
			}
		}
	}

	// Optional /24 neighbor port-scan through the pool (expensive, low yield).
	if cfg.DiscoverScan {
		openCh := make(chan string, 256)
		var scanStored int
		done := make(chan struct{})
		go func() { defer close(done); scanStored, _, _ = manager.ValidateAndStoreStream(ctx, openCh) }()
		found, _ := sc.DiscoverNeighborsStream(ctx, scanner.DiscoverOptions{
			MinDensity: cfg.DiscoverMinDensity, MinPortHits: 3, MaxPorts: 12,
			Workers: cfg.Workers, Timeout: cfg.ConnectTimeout,
		}, func(ipPort string) {
			select {
			case openCh <- ipPort:
			case <-ctx.Done():
			}
		})
		close(openCh)
		<-done
		totalStored += scanStored
		log.Printf("discover: /24 scan found %d open, stored %d", found, scanStored)
	}

	log.Printf("discover: pass done — %d proxies stored", totalStored)
	return nil
}
