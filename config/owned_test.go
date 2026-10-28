package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOwnedCheckConfigPrecedenceAndExclusion(t *testing.T) {
	for _, ext := range []string{"json", "ini"} {
		t.Run(ext, func(t *testing.T) {
			body := `{"checkViaXrok":true,"checkServiceDeep":true,"xrokBinary":"custom-xrok","xrokConfig":"profile.yaml","checkServiceCA":"ca.pem"}`
			if ext == "ini" {
				body = "checkViaXrok=true\ncheckServiceDeep=true\nxrokBinary=custom-xrok\nxrokConfig=profile.yaml\ncheckServiceCA=ca.pem\n"
			}
			path := filepath.Join(t.TempDir(), "config."+ext)
			if err := os.WriteFile(path, []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
			cfg, err := Load([]string{"--config", path})
			if err != nil {
				t.Fatal(err)
			}
			if !cfg.CheckViaXrok || !cfg.CheckServiceDeep || cfg.XrokBinary != "custom-xrok" || cfg.XrokConfig != "profile.yaml" || cfg.CheckServiceCA != "ca.pem" {
				t.Fatalf("lost owned config: %+v", cfg)
			}
			cfg, err = Load([]string{"--config", path, "--checkViaXrok=false", "--checkServiceDeep=false", "--checkServiceURL=https://owned.test/path#key", "--xrokBinary=override"})
			if err != nil {
				t.Fatal(err)
			}
			if cfg.CheckViaXrok || cfg.CheckServiceDeep || cfg.XrokBinary != "override" || cfg.CheckServiceURL == "" {
				t.Fatal("CLI did not override file")
			}
		})
	}
	for _, args := range [][]string{{"--checkViaXrok", "--checkServiceURL=https://owned.test/path#key"}, {"--checkServiceDeep"}} {
		if _, err := Load(args); err == nil {
			t.Fatalf("accepted conflicting settings %v", args)
		}
	}
	cfg, err := Load(nil)
	if err != nil || cfg.CheckViaXrok || cfg.CheckServiceURL != "" || cfg.XrokBinary != "xrok" {
		t.Fatal("changed default validation mode")
	}
}
