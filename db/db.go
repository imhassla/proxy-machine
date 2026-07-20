// Package db provides a SQLite-backed store for proxy results.
package db

import (
	"database/sql"
	"fmt"
	"sort"
	"strings"
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
				last_checked TEXT,
				anon TEXT DEFAULT ''
			)`, table)
		if _, err := d.conn.Exec(stmt); err != nil {
			return fmt.Errorf("create table %s: %w", table, err)
		}
		// Migrate DBs created before the anon column existed. ALTER errors if the column is
		// already present (new tables above) — that's expected, so ignore it.
		_, _ = d.conn.Exec(fmt.Sprintf("ALTER TABLE %s ADD COLUMN anon TEXT DEFAULT ''", table))
	}
	return nil
}

// StoreProxy inserts or updates a proxy row for the given proxy type (anonymity tier unset).
func (d *DB) StoreProxy(proxyType string, proxy string, responseTime float64, lastChecked string) error {
	return d.StoreProxyTier(proxyType, proxy, responseTime, lastChecked, "")
}

// StoreProxyTier inserts or updates a proxy row including its anonymity tier
// (elite | anonymous | transparent | "").
func (d *DB) StoreProxyTier(proxyType string, proxy string, responseTime float64, lastChecked, anon string) error {
	if err := validateProxyType(proxyType); err != nil {
		return err
	}
	stmt := fmt.Sprintf(
		`INSERT OR REPLACE INTO %s (proxy, response_time, last_checked, anon) VALUES (?, ?, ?, ?)`,
		proxyType,
	)
	_, err := d.conn.Exec(stmt, proxy, responseTime, lastChecked, anon)
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
	Anon         string  `json:"anon,omitempty"` // elite | anonymous | transparent | ""
}

// GetProxyRows returns all stored proxies (with metadata) for the given type,
// ordered fastest-first. Used by the API to apply response-time / age filters.
func (d *DB) GetProxyRows(proxyType string) ([]ProxyRow, error) {
	if err := validateProxyType(proxyType); err != nil {
		return nil, err
	}
	rows, err := d.conn.Query(fmt.Sprintf("SELECT proxy, response_time, last_checked, anon FROM %s ORDER BY response_time ASC", proxyType))
	if err != nil {
		return nil, fmt.Errorf("select rows from %s: %w", proxyType, err)
	}
	defer rows.Close()

	var out []ProxyRow
	for rows.Next() {
		var r ProxyRow
		var anon sql.NullString
		if err := rows.Scan(&r.Proxy, &r.ResponseTime, &r.LastChecked, &anon); err != nil {
			return nil, fmt.Errorf("scan row from %s: %w", proxyType, err)
		}
		r.Anon = anon.String
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

// --- geo enrichment (a background process looks up proxy IPs online and stores here) ---

// GeoRow is a proxy IP's geolocation/ASN, keyed by IP (shared across proxy types/ports).
type GeoRow struct {
	IP          string `json:"ip"`
	Country     string `json:"country"`
	CountryCode string `json:"country_code"`
	ASN         string `json:"asn"`
	ISP         string `json:"isp"`
}

// EnsureGeoTable creates the _geo table if it does not exist.
func (d *DB) EnsureGeoTable() error {
	if d.conn == nil {
		return fmt.Errorf("database connection is nil")
	}
	_, err := d.conn.Exec(`CREATE TABLE IF NOT EXISTS _geo (
		ip TEXT PRIMARY KEY,
		country TEXT,
		country_code TEXT,
		asn TEXT,
		isp TEXT,
		updated TEXT
	)`)
	if err != nil {
		return fmt.Errorf("create geo table: %w", err)
	}
	return nil
}

// hostOf strips the port from a "host:port" proxy address (best-effort).
func hostOf(proxy string) string {
	if i := strings.LastIndex(proxy, ":"); i > 0 {
		return proxy[:i]
	}
	return proxy
}

// ProxyIPsMissingGeo returns up to limit distinct proxy IPs (across all per-type tables)
// that have no row in _geo yet — the work queue for the enricher.
func (d *DB) ProxyIPsMissingGeo(limit int) ([]string, error) {
	if d.conn == nil {
		return nil, fmt.Errorf("database connection is nil")
	}
	if err := d.EnsureGeoTable(); err != nil {
		return nil, err
	}
	known := map[string]struct{}{}
	rows, err := d.conn.Query("SELECT ip FROM _geo")
	if err != nil {
		return nil, fmt.Errorf("select geo ips: %w", err)
	}
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			rows.Close()
			return nil, err
		}
		known[ip] = struct{}{}
	}
	rows.Close()

	seen := map[string]struct{}{}
	var out []string
	for table := range allowedTypes {
		prox, err := d.conn.Query(fmt.Sprintf("SELECT proxy FROM %s", table))
		if err != nil {
			continue
		}
		for prox.Next() {
			var p string
			if err := prox.Scan(&p); err != nil {
				continue
			}
			ip := hostOf(p)
			if _, k := known[ip]; k {
				continue
			}
			if _, s := seen[ip]; s {
				continue
			}
			seen[ip] = struct{}{}
			out = append(out, ip)
			if len(out) >= limit {
				prox.Close()
				return out, nil
			}
		}
		prox.Close()
	}
	return out, nil
}

// StoreGeo upserts geolocation rows.
func (d *DB) StoreGeo(rows []GeoRow, updated string) error {
	if d.conn == nil {
		return fmt.Errorf("database connection is nil")
	}
	if len(rows) == 0 {
		return nil
	}
	if err := d.EnsureGeoTable(); err != nil {
		return err
	}
	tx, err := d.conn.Begin()
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	stmt, err := tx.Prepare("INSERT OR REPLACE INTO _geo (ip, country, country_code, asn, isp, updated) VALUES (?, ?, ?, ?, ?, ?)")
	if err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("prepare geo insert: %w", err)
	}
	defer stmt.Close()
	for _, r := range rows {
		if _, err := stmt.Exec(r.IP, r.Country, r.CountryCode, r.ASN, r.ISP, updated); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("insert geo %q: %w", r.IP, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit geo: %w", err)
	}
	return nil
}

// PruneGeoOrphans deletes _geo rows whose IP is no longer the host of any stored proxy across
// the per-type tables, returning how many were removed. Proxy IPs churn heavily (thousands
// pruned per day), and _geo is otherwise insert-only — including empty markers for
// un-geolocatable IPs — so without this it grows without bound over long uptime, which also
// bloats ProxyIPsMissingGeo's full-table scan every cycle. Keeps _geo bounded to the live pool.
func (d *DB) PruneGeoOrphans() (int, error) {
	if d.conn == nil {
		return 0, fmt.Errorf("database connection is nil")
	}
	if err := d.EnsureGeoTable(); err != nil {
		return 0, err
	}
	// Live proxy hosts across every per-type table.
	live := map[string]struct{}{}
	for table := range allowedTypes {
		rows, err := d.conn.Query(fmt.Sprintf("SELECT proxy FROM %s", table))
		if err != nil {
			continue
		}
		for rows.Next() {
			var p string
			if err := rows.Scan(&p); err != nil {
				continue
			}
			live[hostOf(p)] = struct{}{}
		}
		rows.Close()
	}
	// Collect _geo IPs not backed by any live proxy.
	rows, err := d.conn.Query("SELECT ip FROM _geo")
	if err != nil {
		return 0, fmt.Errorf("select geo ips: %w", err)
	}
	var orphans []string
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			rows.Close()
			return 0, err
		}
		if _, ok := live[ip]; !ok {
			orphans = append(orphans, ip)
		}
	}
	rows.Close()
	if len(orphans) == 0 {
		return 0, nil
	}
	tx, err := d.conn.Begin()
	if err != nil {
		return 0, fmt.Errorf("begin: %w", err)
	}
	stmt, err := tx.Prepare("DELETE FROM _geo WHERE ip = ?")
	if err != nil {
		_ = tx.Rollback()
		return 0, fmt.Errorf("prepare geo delete: %w", err)
	}
	defer stmt.Close()
	for _, ip := range orphans {
		if _, err := stmt.Exec(ip); err != nil {
			_ = tx.Rollback()
			return 0, fmt.Errorf("delete geo %q: %w", ip, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit geo prune: %w", err)
	}
	return len(orphans), nil
}

// CountByCountry returns proxy-IP counts per country (from _geo), most first — for the
// dashboard's TOP COUNTRIES panel.
func (d *DB) CountByCountry() ([]struct {
	Country string
	Code    string
	Count   int
}, error) {
	if d.conn == nil {
		return nil, fmt.Errorf("database connection is nil")
	}
	if err := d.EnsureGeoTable(); err != nil {
		return nil, err
	}
	// Exclude empty-marker rows (IPs ip-api couldn't geolocate — stored so they aren't
	// re-queried forever, but they carry no country).
	rows, err := d.conn.Query(`SELECT country, country_code, COUNT(*)
		FROM _geo WHERE country_code IS NOT NULL AND country_code != '' GROUP BY country_code ORDER BY 3 DESC`)
	if err != nil {
		return nil, fmt.Errorf("count by country: %w", err)
	}
	defer rows.Close()
	var out []struct {
		Country string
		Code    string
		Count   int
	}
	for rows.Next() {
		var c struct {
			Country string
			Code    string
			Count   int
		}
		if err := rows.Scan(&c.Country, &c.Code, &c.Count); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// CountByNetwork returns proxy-IP counts per ASN/network (from _geo), most first — for the
// dashboard's TOP NETWORKS panel. Capped at 12 rows.
func (d *DB) CountByNetwork() ([]struct {
	Network string
	Count   int
}, error) {
	if d.conn == nil {
		return nil, fmt.Errorf("database connection is nil")
	}
	if err := d.EnsureGeoTable(); err != nil {
		return nil, err
	}
	rows, err := d.conn.Query(`SELECT COALESCE(NULLIF(asn,''),'?'), COUNT(*) FROM _geo
		WHERE asn IS NOT NULL AND asn != '' GROUP BY asn ORDER BY 2 DESC LIMIT 12`)
	if err != nil {
		return nil, fmt.Errorf("count by network: %w", err)
	}
	defer rows.Close()
	var out []struct {
		Network string
		Count   int
	}
	for rows.Next() {
		var c struct {
			Network string
			Count   int
		}
		if err := rows.Scan(&c.Network, &c.Count); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// GeoByIPs returns geo rows for the given IPs (missing IPs simply absent from the map). It
// queries in chunked `IN (...)` batches so filtering a large pool by geo stays fast.
func (d *DB) GeoByIPs(ips []string) (map[string]GeoRow, error) {
	out := map[string]GeoRow{}
	if d.conn == nil || len(ips) == 0 {
		return out, nil
	}
	if err := d.EnsureGeoTable(); err != nil {
		return nil, err
	}
	const chunk = 400 // stay well under SQLite's parameter limit
	for start := 0; start < len(ips); start += chunk {
		end := start + chunk
		if end > len(ips) {
			end = len(ips)
		}
		batch := ips[start:end]
		ph := make([]string, len(batch))
		args := make([]any, len(batch))
		for i, ip := range batch {
			ph[i] = "?"
			args[i] = ip
		}
		q := "SELECT ip, country, country_code, asn, isp FROM _geo WHERE ip IN (" + strings.Join(ph, ",") + ")"
		rows, err := d.conn.Query(q, args...)
		if err != nil {
			return nil, fmt.Errorf("geo by ips: %w", err)
		}
		for rows.Next() {
			var g GeoRow
			if err := rows.Scan(&g.IP, &g.Country, &g.CountryCode, &g.ASN, &g.ISP); err != nil {
				rows.Close()
				return nil, err
			}
			out[g.IP] = g
		}
		rows.Close()
	}
	return out, nil
}
