package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"proxymachine/checker"
	"proxymachine/config"
	"proxymachine/pkg/checkservice"
)

func setupOwnedChecks(ctx context.Context, cfg *config.Config, manager *checker.CheckManager) (*checkservice.Tunnel, error) {
	descriptor, ca := cfg.CheckServiceURL, cfg.CheckServiceCA
	var tunnel *checkservice.Tunnel
	if cfg.CheckViaXrok {
		var err error
		tunnel, err = checkservice.StartXrok(ctx, checkservice.XrokOptions{Binary: cfg.XrokBinary, Config: cfg.XrokConfig, CAFile: ca})
		if err != nil {
			return nil, fmt.Errorf("start owned check service: %w", err)
		}
		descriptor, ca = tunnel.Descriptor, tunnel.CAFile
	}
	if descriptor != "" {
		if err := manager.UseOwnedService(descriptor, ca); err != nil {
			if tunnel != nil {
				tunnel.Close()
			}
			return nil, err
		}
		log.Printf("checker: owned signed HTTPS checks enabled (deep=%t; no public validation/canary fallback; anonymity tier unknown)", cfg.CheckServiceDeep)
	}
	return tunnel, nil
}

// runCheckService lets a checker on another machine use a locally configured
// xrok profile. Stdout is a single reusable descriptor; no credentials are shown.
func runCheckService(args []string) error {
	cfg, err := config.Load(args)
	if err != nil {
		return err
	}
	if cfg.CheckServiceURL != "" {
		return fmt.Errorf("check-service starts a new service; checkServiceURL belongs on the checker")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	t, err := checkservice.StartXrok(ctx, checkservice.XrokOptions{Binary: cfg.XrokBinary, Config: cfg.XrokConfig, CAFile: cfg.CheckServiceCA})
	if err != nil {
		return err
	}
	defer t.Close()
	fmt.Println(t.Descriptor)
	select {
	case <-ctx.Done():
		return nil
	case <-t.Done():
		if ctx.Err() != nil {
			return nil
		}
		return fmt.Errorf("owned xrok tunnel exited: %w", t.Err())
	}
}
