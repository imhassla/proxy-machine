package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"proxymachine/api"
	"proxymachine/checker"
	"proxymachine/config"
	"proxymachine/db"
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

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	server := api.New(cfg.APIAddr, manager, database)
	relayServer := relay.New(cfg, manager, database)

	var checkerErr error
	checkerDone := make(chan struct{})
	go func() {
		defer close(checkerDone)
		checkerErr = manager.Start(ctx)
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
