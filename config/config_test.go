package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoad_Defaults(t *testing.T) {
	cfg, err := Load([]string{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Workers != 4 {
		t.Errorf("expected Workers=4, got %d", cfg.Workers)
	}
	if cfg.Timeout != 30*time.Second {
		t.Errorf("expected Timeout=30s, got %v", cfg.Timeout)
	}
	if cfg.DBPath != "data.db" {
		t.Errorf("expected DBPath=data.db, got %s", cfg.DBPath)
	}
}

func TestLoad_JSON(t *testing.T) {
	dir := t.TempDir()
	jsonFile := filepath.Join(dir, "config.json")
	content := `{"workers": 8, "timeout": "1m", "dbPath": "test.db"}`
	if err := os.WriteFile(jsonFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}
	cfg, err := Load([]string{"-config", jsonFile})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Workers != 8 {
		t.Errorf("expected Workers=8, got %d", cfg.Workers)
	}
	if cfg.Timeout != 1*time.Minute {
		t.Errorf("expected Timeout=1m, got %v", cfg.Timeout)
	}
	if cfg.DBPath != "test.db" {
		t.Errorf("expected DBPath=test.db, got %s", cfg.DBPath)
	}
}

func TestLoad_JSON_Partial(t *testing.T) {
	dir := t.TempDir()
	jsonFile := filepath.Join(dir, "config.json")
	content := `{"workers": 10}`
	if err := os.WriteFile(jsonFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}
	cfg, err := Load([]string{"-config", jsonFile})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Workers != 10 {
		t.Errorf("expected Workers=10, got %d", cfg.Workers)
	}
	if cfg.Timeout != 30*time.Second {
		t.Errorf("expected default Timeout=30s, got %v", cfg.Timeout)
	}
	if cfg.DBPath != "data.db" {
		t.Errorf("expected default DBPath=data.db, got %s", cfg.DBPath)
	}
}

func TestLoad_INI(t *testing.T) {
	dir := t.TempDir()
	iniFile := filepath.Join(dir, "config.ini")
	content := `workers=8
timeout=1m
dbPath=test.db
`
	if err := os.WriteFile(iniFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}
	cfg, err := Load([]string{"-config", iniFile})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Workers != 8 {
		t.Errorf("expected Workers=8, got %d", cfg.Workers)
	}
	if cfg.Timeout != 1*time.Minute {
		t.Errorf("expected Timeout=1m, got %v", cfg.Timeout)
	}
	if cfg.DBPath != "test.db" {
		t.Errorf("expected DBPath=test.db, got %s", cfg.DBPath)
	}
}

func TestLoad_INI_DatabaseSection(t *testing.T) {
	dir := t.TempDir()
	iniFile := filepath.Join(dir, "config.ini")
	// A NON-default path so this actually asserts the [database] path key is parsed
	// (matching python/config.ini); a default would pass even if parsing did nothing.
	content := `[database]
path = "custom-proxies.db"
workers = 5
`
	if err := os.WriteFile(iniFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}
	cfg, err := Load([]string{"-config", iniFile})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Workers != 5 {
		t.Errorf("expected Workers=5, got %d", cfg.Workers)
	}
	if cfg.DBPath != "custom-proxies.db" {
		t.Errorf("expected DBPath=custom-proxies.db (parsed from [database] path), got %s", cfg.DBPath)
	}
}

func TestLoad_INI_GlobalDBPath(t *testing.T) {
	dir := t.TempDir()
	iniFile := filepath.Join(dir, "config.ini")
	content := `db.path = other.db
`
	if err := os.WriteFile(iniFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}
	cfg, err := Load([]string{"-config", iniFile})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.DBPath != "other.db" {
		t.Errorf("expected DBPath=other.db, got %s", cfg.DBPath)
	}
}

func TestLoad_CLI_Override(t *testing.T) {
	dir := t.TempDir()
	jsonFile := filepath.Join(dir, "config.json")
	content := `{"workers": 8, "timeout": "1m", "dbPath": "test.db"}`
	if err := os.WriteFile(jsonFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}
	cfg, err := Load([]string{"-config", jsonFile, "-workers", "16", "-timeout", "2m", "-dbPath", "other.db"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Workers != 16 {
		t.Errorf("expected Workers=16, got %d", cfg.Workers)
	}
	if cfg.Timeout != 2*time.Minute {
		t.Errorf("expected Timeout=2m, got %v", cfg.Timeout)
	}
	if cfg.DBPath != "other.db" {
		t.Errorf("expected DBPath=other.db, got %s", cfg.DBPath)
	}
}

func TestLoad_CLI(t *testing.T) {
	cfg, err := Load([]string{"-workers", "8", "-timeout", "1m", "-dbPath", "cli.db"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Workers != 8 {
		t.Errorf("expected Workers=8, got %d", cfg.Workers)
	}
	if cfg.Timeout != 1*time.Minute {
		t.Errorf("expected Timeout=1m, got %v", cfg.Timeout)
	}
	if cfg.DBPath != "cli.db" {
		t.Errorf("expected DBPath=cli.db, got %s", cfg.DBPath)
	}
}

func TestLoad_MissingConfig(t *testing.T) {
	_, err := Load([]string{"-config", "/nonexistent/path/config.json"})
	if err == nil {
		t.Error("expected error for missing config file")
	}
}

func TestLoad_InvalidConfigValue(t *testing.T) {
	dir := t.TempDir()
	jsonFile := filepath.Join(dir, "bad.json")
	content := `{"timeout": "invalid"}`
	if err := os.WriteFile(jsonFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}
	_, err := Load([]string{"-config", jsonFile})
	if err == nil {
		t.Error("expected error for invalid config value")
	}
}

func TestLoad_InvalidCLI(t *testing.T) {
	_, err := Load([]string{"-timeout", "badvalue"})
	if err == nil {
		t.Error("expected error for invalid CLI value")
	}
}

func TestLoad_JSON_InvalidWorkers(t *testing.T) {
	dir := t.TempDir()
	jsonFile := filepath.Join(dir, "bad.json")
	content := `{"workers": "notanumber"}`
	if err := os.WriteFile(jsonFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}
	_, err := Load([]string{"-config", jsonFile})
	if err == nil {
		t.Error("expected error for invalid workers in JSON")
	}
}
