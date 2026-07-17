// Package db provides a SQLite-backed store for proxy results.
package db

import (
	"database/sql"
	"fmt"
	"sort"
	"sync/atomic"

	_ "modernc.org/sqlite"
)

var allowedTypes = map[string]struct{}{
	"http":   {},
	"https":  {},
	"socks4": {},
	"socks5": {},
}

// DB wraps a SQLite database connection and provides proxy CRUD operations.
type DB struct {
	conn *sql.DB
}

// Open opens a SQLite database at the given data source name.
func Open(dataSourceName string) (*DB, error) {
	conn, err := sql.Open("sqlite", dataSourceName)
	if err != nil {
		return nil, fmt.Errorf("open sqlite database: %w", err)
	}
	// Serialize all access through a single connection. The checker writes validated
	// proxies on every cycle while the API and relay read concurrently; with the default
	// multi-connection pool that races to SQLITE_BUSY (which silently dropped freshly
	// validated proxies). One connection makes reads queue behind the tiny upserts
	// instead of erroring — simplest correct fix at this scale.
	conn.SetMaxOpenConns(1)
	if err := conn.Ping(); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("ping sqlite database: %w", err)
	}
	// busy_timeout: SetMaxOpenConns(1) stops in-process SQLITE_BUSY, but a SECOND process
	// (the `scan` subcommand run against the live daemon's DB) can still collide — wait up
	// to 5s for the lock instead of erroring and dropping the write. WAL lets that reader and
	// the daemon's writer proceed concurrently. Best-effort: a driver/build lacking either
	// pragma shouldn't fail startup (WAL is a no-op on :memory:).
	for _, pragma := range []string{"PRAGMA busy_timeout=5000", "PRAGMA journal_mode=WAL"} {
		if _, err := conn.Exec(pragma); err != nil {
			// Non-fatal — log-by-ignore; the DB still works without the tuning.
			_ = err
		}
	}
	return &DB{conn: conn}, nil
}

// memDBSeq names each in-memory database uniquely so OpenInMemory() truly returns an
// ISOLATED database per call (a fixed "file::memory:?cache=shared" name is process-wide
// shared, which let separate tests cross-contaminate).
var memDBSeq atomic.Uint64

// OpenInMemory opens a new, isolated in-memory SQLite database (for unit tests).
func OpenInMemory() (*DB, error) {
	name := fmt.Sprintf("file:memdb%d?mode=memory&cache=shared&_pragma=foreign_keys(1)", memDBSeq.Add(1))
	return Open(name)
}

// Close closes the underlying database connection.
func (d *DB) Close() error {
	if d.conn == nil {
		return nil
	}
	return d.conn.Close()
}

// Init creates the http, https, socks4 and socks5 tables if they do not exist.
func (d *DB) Init() error {
	if d.conn == nil {
		return fmt.Errorf("database connection is nil")
	}

	for _, table := range []string{"http", "https", "socks4", "socks5"} {
		stmt := fmt.Sprintf(
			`CREATE TABLE IF NOT EXISTS %s (
				proxy TEXT PRIMARY KEY,
				response_time REAL,
				last_checked TEXT
			)`, table)
		if _, err := d.conn.Exec(stmt); err != nil {
			return fmt.Errorf("create table %s: %w", table, err)
		}
	}
	return nil
}

// StoreProxy inserts or updates a proxy row for the given proxy type.
func (d *DB) StoreProxy(proxyType string, proxy string, responseTime float64, lastChecked string) error {
	if err := validateProxyType(proxyType); err != nil {
		return err
	}
	stmt := fmt.Sprintf(
		`INSERT OR REPLACE INTO %s (proxy, response_time, last_checked) VALUES (?, ?, ?)`,
		proxyType,
	)
	_, err := d.conn.Exec(stmt, proxy, responseTime, lastChecked)
	if err != nil {
		return fmt.Errorf("store proxy in %s: %w", proxyType, err)
	}
	return nil
}

// GetProxiesByType returns the proxy addresses stored for the given proxy type.
func (d *DB) GetProxiesByType(proxyType string) ([]string, error) {
	if err := validateProxyType(proxyType); err != nil {
		return nil, err
	}
	rows, err := d.conn.Query(fmt.Sprintf("SELECT proxy FROM %s", proxyType))
	if err != nil {
		return nil, fmt.Errorf("select proxies from %s: %w", proxyType, err)
	}
	defer rows.Close()

	var proxies []string
	for rows.Next() {
		var proxy string
		if err := rows.Scan(&proxy); err != nil {
			return nil, fmt.Errorf("scan proxy from %s: %w", proxyType, err)
		}
		proxies = append(proxies, proxy)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate proxies from %s: %w", proxyType, err)
	}

	// Deterministic ordering for tests.
	sort.Strings(proxies)
	return proxies, nil
}

// CountByType returns the number of stored proxies of the given type (cheap COUNT(*),
// used by /stats and /metrics without materializing every row).
func (d *DB) CountByType(proxyType string) (int, error) {
	if err := validateProxyType(proxyType); err != nil {
		return 0, err
	}
	var n int
	if err := d.conn.QueryRow(fmt.Sprintf("SELECT COUNT(*) FROM %s", proxyType)).Scan(&n); err != nil {
		return 0, fmt.Errorf("count %s: %w", proxyType, err)
	}
	return n, nil
}

// ProxyRow is a stored proxy with its validation metadata. JSON tags match the
// reference API shape (proxy / response_time / last_checked).
type ProxyRow struct {
	Proxy        string  `json:"proxy"`
	ResponseTime float64 `json:"response_time"`
	LastChecked  string  `json:"last_checked"`
}

// GetProxyRows returns all stored proxies (with metadata) for the given type,
// ordered fastest-first. Used by the API to apply response-time / age filters.
func (d *DB) GetProxyRows(proxyType string) ([]ProxyRow, error) {
	if err := validateProxyType(proxyType); err != nil {
		return nil, err
	}
	rows, err := d.conn.Query(fmt.Sprintf("SELECT proxy, response_time, last_checked FROM %s ORDER BY response_time ASC", proxyType))
	if err != nil {
		return nil, fmt.Errorf("select rows from %s: %w", proxyType, err)
	}
	defer rows.Close()

	var out []ProxyRow
	for rows.Next() {
		var r ProxyRow
		if err := rows.Scan(&r.Proxy, &r.ResponseTime, &r.LastChecked); err != nil {
			return nil, fmt.Errorf("scan row from %s: %w", proxyType, err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate rows from %s: %w", proxyType, err)
	}
	return out, nil
}

// PruneStale deletes proxies across all per-type tables whose last_checked is older than
// cutoff (a "2006-01-02 15:04:05" UTC string — lexicographically sortable, so a string
// comparison is a time comparison). Bounds table growth (and thus per-cycle recheck cost)
// over long uptime. Returns the number of rows removed.
func (d *DB) PruneStale(cutoff string) (int, error) {
	if d.conn == nil {
		return 0, fmt.Errorf("database connection is nil")
	}
	var total int
	for table := range allowedTypes {
		res, err := d.conn.Exec(fmt.Sprintf("DELETE FROM %s WHERE last_checked < ?", table), cutoff)
		if err != nil {
			return total, fmt.Errorf("prune %s: %w", table, err)
		}
		if n, err := res.RowsAffected(); err == nil {
			total += int(n)
		}
	}
	return total, nil
}

// DeleteProxies removes the given proxies from a type's table (pruning dead proxies).
// A nil/empty list is a no-op.
func (d *DB) DeleteProxies(proxyType string, proxies []string) error {
	if err := validateProxyType(proxyType); err != nil {
		return err
	}
	if len(proxies) == 0 {
		return nil
	}
	return d.deleteFrom(proxyType, "proxy", proxies)
}

// DeleteScanResults removes consumed ip:port entries from _scan_results.
// A nil/empty list is a no-op.
func (d *DB) DeleteScanResults(ipPorts []string) error {
	if len(ipPorts) == 0 {
		return nil
	}
	return d.deleteFrom("_scan_results", "ip_port", ipPorts)
}

// deleteFrom deletes rows matching values of a column within one transaction.
// table/column are caller-controlled (never user input): the per-type tables come
// from validateProxyType and the scan-results table/column are constants.
func (d *DB) deleteFrom(table, column string, values []string) error {
	if d.conn == nil {
		return fmt.Errorf("database connection is nil")
	}
	tx, err := d.conn.Begin()
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	stmt, err := tx.Prepare(fmt.Sprintf("DELETE FROM %s WHERE %s = ?", table, column))
	if err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("prepare delete from %s: %w", table, err)
	}
	defer stmt.Close()
	for _, v := range values {
		if _, err := stmt.Exec(v); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("delete %q from %s: %w", v, table, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit delete from %s: %w", table, err)
	}
	return nil
}

func validateProxyType(proxyType string) error {
	if _, ok := allowedTypes[proxyType]; !ok {
		return fmt.Errorf("invalid proxy type: %q", proxyType)
	}
	return nil
}

// HealthRow persists one upstream's relay health across restarts.
type HealthRow struct {
	Addr    string // "type://addr"
	EWMA    float64
	HasData bool
	Fails   int
}

// EnsureHealthTable creates the _relay_health table if it does not exist.
func (d *DB) EnsureHealthTable() error {
	if d.conn == nil {
		return fmt.Errorf("database connection is nil")
	}
	_, err := d.conn.Exec(`CREATE TABLE IF NOT EXISTS _relay_health (
		addr TEXT PRIMARY KEY,
		ewma REAL,
		has_data INTEGER,
		fails INTEGER
	)`)
	if err != nil {
		return fmt.Errorf("create relay health table: %w", err)
	}
	return nil
}

// LoadHealth returns all persisted upstream health rows (empty if the table is absent).
func (d *DB) LoadHealth() ([]HealthRow, error) {
	if d.conn == nil {
		return nil, fmt.Errorf("database connection is nil")
	}
	if err := d.EnsureHealthTable(); err != nil {
		return nil, err
	}
	rows, err := d.conn.Query("SELECT addr, ewma, has_data, fails FROM _relay_health")
	if err != nil {
		return nil, fmt.Errorf("select relay health: %w", err)
	}
	defer rows.Close()
	var out []HealthRow
	for rows.Next() {
		var r HealthRow
		var hasData int
		if err := rows.Scan(&r.Addr, &r.EWMA, &hasData, &r.Fails); err != nil {
			return nil, fmt.Errorf("scan relay health: %w", err)
		}
		r.HasData = hasData != 0
		out = append(out, r)
	}
	return out, rows.Err()
}

// SaveHealth replaces the persisted health snapshot with the given rows (one transaction).
func (d *DB) SaveHealth(rows []HealthRow) error {
	if d.conn == nil {
		return fmt.Errorf("database connection is nil")
	}
	if err := d.EnsureHealthTable(); err != nil {
		return err
	}
	tx, err := d.conn.Begin()
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	if _, err := tx.Exec("DELETE FROM _relay_health"); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("clear relay health: %w", err)
	}
	stmt, err := tx.Prepare("INSERT OR REPLACE INTO _relay_health (addr, ewma, has_data, fails) VALUES (?, ?, ?, ?)")
	if err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("prepare relay health insert: %w", err)
	}
	defer stmt.Close()
	for _, r := range rows {
		hasData := 0
		if r.HasData {
			hasData = 1
		}
		if _, err := stmt.Exec(r.Addr, r.EWMA, hasData, r.Fails); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("insert relay health %q: %w", r.Addr, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit relay health: %w", err)
	}
	return nil
}

// EnsureScanResultsTable creates the _scan_results table if it does not exist.
func (d *DB) EnsureScanResultsTable() error {
	if d.conn == nil {
		return fmt.Errorf("database connection is nil")
	}
	_, err := d.conn.Exec(`CREATE TABLE IF NOT EXISTS _scan_results (
		ip_port TEXT PRIMARY KEY
	)`)
	if err != nil {
		return fmt.Errorf("create scan results table: %w", err)
	}
	return nil
}

// StoreScanResults inserts or replaces the given ip:port entries in the
// _scan_results table.
func (d *DB) StoreScanResults(ipPorts []string) error {
	if d.conn == nil {
		return fmt.Errorf("database connection is nil")
	}
	tx, err := d.conn.Begin()
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	stmt, err := tx.Prepare("INSERT OR REPLACE INTO _scan_results (ip_port) VALUES (?)")
	if err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("prepare scan result insert: %w", err)
	}
	defer stmt.Close()
	for _, ipPort := range ipPorts {
		if _, err := stmt.Exec(ipPort); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("store scan result %q: %w", ipPort, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit scan results: %w", err)
	}
	return nil
}

// GetScanResults returns all stored open ip:port results.
func (d *DB) GetScanResults() ([]string, error) {
	if d.conn == nil {
		return nil, fmt.Errorf("database connection is nil")
	}
	rows, err := d.conn.Query("SELECT ip_port FROM _scan_results")
	if err != nil {
		return nil, fmt.Errorf("select scan results: %w", err)
	}
	defer rows.Close()

	var results []string
	for rows.Next() {
		var r string
		if err := rows.Scan(&r); err != nil {
			return nil, fmt.Errorf("scan result: %w", err)
		}
		results = append(results, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate scan results: %w", err)
	}
	sort.Strings(results)
	return results, nil
}
