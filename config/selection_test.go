package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSelectionPolicyConfiguration(t *testing.T) {
	for _, ext := range []string{"json", "ini"} {
		t.Run(ext, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "config."+ext)
			body := `{"selectionPolicy":"stable"}`
			if ext == "ini" {
				body = "selectionPolicy=stable\n"
			}
			if err := os.WriteFile(p, []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
			c, err := Load([]string{"--config", p})
			if err != nil || c.SelectionPolicy != "stable" {
				t.Fatalf("%+v %v", c, err)
			}
			c, err = Load([]string{"--config", p, "--selectionPolicy", "rotate"})
			if err != nil || c.SelectionPolicy != "rotate" {
				t.Fatalf("%+v %v", c, err)
			}
		})
	}
	for _, args := range [][]string{{"--selectionPolicy", "invalid"}, {"--selectionPolicy", "stable", "--chainLength", "2"}} {
		if _, err := Load(args); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
}

func TestUDPAndCandidatePolicies(t *testing.T) {
	c, err := Load([]string{"--udpMode", "off", "--maxCandidates", "40"})
	if err != nil || c.UDPMode != "off" || c.MaxCandidates != 40 {
		t.Fatalf("%+v %v", c, err)
	}
	for _, args := range [][]string{{"--udpMode", "proxy"}, {"--maxCandidates", "2"}} {
		if _, err := Load(args); err == nil {
			t.Fatal("invalid policy accepted", args)
		}
	}
	for _, ext := range []string{"json", "ini"} {
		p := filepath.Join(t.TempDir(), "config."+ext)
		body := `{"udpMode":"off","maxCandidates":40}`
		if ext == "ini" {
			body = "udpMode=off\nmaxCandidates=40\n"
		}
		if err := os.WriteFile(p, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		c, err := Load([]string{"--config", p})
		if err != nil || c.UDPMode != "off" || c.MaxCandidates != 40 {
			t.Fatalf("%+v %v", c, err)
		}
	}
}
