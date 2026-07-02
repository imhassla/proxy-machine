package db

import (
	"testing"
)

func setupDB(t *testing.T) *DB {
	t.Helper()
	db, err := OpenInMemory()
	if err != nil {
		t.Fatalf("failed to open in-memory database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Init(); err != nil {
		t.Fatalf("failed to initialize database: %v", err)
	}
	return db
}

func TestInitCreatesTables(t *testing.T) {
	db, err := OpenInMemory()
	if err != nil {
		t.Fatalf("failed to open in-memory database: %v", err)
	}
	defer db.Close()

	if err := db.Init(); err != nil {
		t.Fatalf("Init() failed: %v", err)
	}

	tables := []string{"http", "https", "socks4", "socks5"}
	for _, table := range tables {
		var name string
		query := "SELECT name FROM sqlite_master WHERE type='table' AND name=?"
		err := db.conn.QueryRow(query, table).Scan(&name)
		if err != nil {
			t.Errorf("table %s was not created: %v", table, err)
		}
		if name != table {
			t.Errorf("expected table name %s, got %s", table, name)
		}
	}
}

func TestStoreProxy(t *testing.T) {
	db := setupDB(t)

	err := db.StoreProxy("http", "192.168.1.1:8080", 0.123, "2023-01-01T00:00:00Z")
	if err != nil {
		t.Fatalf("StoreProxy() failed: %v", err)
	}

	proxies, err := db.GetProxiesByType("http")
	if err != nil {
		t.Fatalf("GetProxiesByType() failed: %v", err)
	}

	if len(proxies) != 1 {
		t.Fatalf("expected 1 proxy, got %d", len(proxies))
	}

	if proxies[0] != "192.168.1.1:8080" {
		t.Errorf("expected proxy '192.168.1.1:8080', got '%s'", proxies[0])
	}
}

func TestStoreProxyUpdatesExisting(t *testing.T) {
	db := setupDB(t)

	err := db.StoreProxy("https", "10.0.0.1:443", 0.5, "2023-01-01T00:00:00Z")
	if err != nil {
		t.Fatalf("first StoreProxy() failed: %v", err)
	}

	err = db.StoreProxy("https", "10.0.0.1:443", 0.2, "2023-06-01T00:00:00Z")
	if err != nil {
		t.Fatalf("second StoreProxy() failed: %v", err)
	}

	var responseTime float64
	var lastChecked string
	err = db.conn.QueryRow("SELECT response_time, last_checked FROM https WHERE proxy = ?", "10.0.0.1:443").Scan(&responseTime, &lastChecked)
	if err != nil {
		t.Fatalf("failed to query updated proxy: %v", err)
	}

	if responseTime != 0.2 {
		t.Errorf("expected response_time 0.2, got %f", responseTime)
	}

	if lastChecked != "2023-06-01T00:00:00Z" {
		t.Errorf("expected last_checked '2023-06-01T00:00:00Z', got '%s'", lastChecked)
	}
}

func TestStoreProxyInvalidType(t *testing.T) {
	db := setupDB(t)

	err := db.StoreProxy("invalid", "proxy:1234", 0.1, "now")
	if err == nil {
		t.Error("expected error for invalid proxy type, got nil")
	}
}

func TestGetProxiesByType(t *testing.T) {
	db := setupDB(t)

	proxies := []string{"192.168.1.1:8080", "10.0.0.1:8080", "172.16.0.1:8080"}
	for _, p := range proxies {
		if err := db.StoreProxy("http", p, 0.1, "now"); err != nil {
			t.Fatalf("StoreProxy() failed: %v", err)
		}
	}

	// Store a proxy of a different type to ensure filtering works.
	if err := db.StoreProxy("socks5", "10.0.0.2:1080", 0.2, "now"); err != nil {
		t.Fatalf("StoreProxy() failed: %v", err)
	}

	results, err := db.GetProxiesByType("http")
	if err != nil {
		t.Fatalf("GetProxiesByType() failed: %v", err)
	}

	if len(results) != 3 {
		t.Fatalf("expected 3 proxies, got %d", len(results))
	}

	expected := []string{"10.0.0.1:8080", "172.16.0.1:8080", "192.168.1.1:8080"}
	for i, p := range results {
		if p != expected[i] {
			t.Errorf("expected proxy[%d] = '%s', got '%s'", i, expected[i], p)
		}
	}
}

func TestGetProxiesByTypeEmpty(t *testing.T) {
	db := setupDB(t)

	results, err := db.GetProxiesByType("socks4")
	if err != nil {
		t.Fatalf("GetProxiesByType() failed: %v", err)
	}

	if len(results) != 0 {
		t.Errorf("expected 0 proxies, got %d", len(results))
	}
}

func TestGetProxiesByTypeInvalidType(t *testing.T) {
	db := setupDB(t)

	_, err := db.GetProxiesByType("invalid")
	if err == nil {
		t.Error("expected error for invalid proxy type, got nil")
	}
}
