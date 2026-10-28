package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"proxymachine/pkg/relay"
)

func runProbe(args []string) error {
	fs := flag.NewFlagSet("probe", flag.ContinueOnError)
	upstream := fs.String("proxy", "", "Typed proxy URL, e.g. http://127.0.0.1:3333")
	target := fs.String("url", "", "Explicit controlled HTTP/HTTPS endpoint")
	digest := fs.String("sha256", "", "Expected response SHA-256 (optional)")
	budget := fs.Duration("timeout", 15*time.Second, "Total probe timeout (maximum 30s)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *budget <= 0 {
		return fmt.Errorf("timeout must be positive")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, *budget)
	defer cancel()
	result, err := relay.Probe(ctx, *upstream, *target, relay.ProbeOptions{ExpectedSHA256: *digest})
	if e := json.NewEncoder(os.Stdout).Encode(result); e != nil {
		return e
	}
	return err
}
