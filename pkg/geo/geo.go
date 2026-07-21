// Package geo enriches stored proxy IPs with country/ASN/ISP via an ONLINE lookup
// (ip-api.com's free batch endpoint — no API key, no local database), writing results to
// the DB's _geo table. It runs as its own background loop, independent of the checker, so
// the validation pipeline never waits on geo lookups.
package geo

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"

	"proxymachine/db"
)

// ip-api.com free tier: ~45 requests/min, HTTP only, up to 100 IPs per batch call.
const (
	batchURL   = "http://ip-api.com/batch?fields=status,query,country,countryCode,isp,as"
	batchSize  = 100
	pace       = 2 * time.Second  // between batches → ~30/min, safely under the 45/min cap
	idleWait   = 30 * time.Second // when every proxy IP already has geo
	userAgent  = "Mozilla/5.0 (compatible; proxy-machine geo-enricher)"
	maxRespLen = 1 << 20
)

// geoStore is the DB surface the enricher needs.
type geoStore interface {
	ProxyIPsMissingGeo(limit int) ([]string, error)
	StoreGeo(rows []db.GeoRow, updated string) error
}

// Enricher looks up proxy-IP geolocation in the background.
type Enricher struct {
	db       geoStore
	client   *http.Client
	url      string // batch endpoint (overridable in tests)
	now      func() time.Time
	resolved atomic.Int64 // lifetime count of IPs actually geolocated (excludes empty markers)
}

// New returns an Enricher backed by the given DB.
func New(database geoStore) *Enricher {
	return &Enricher{
		db: database,
		client: &http.Client{
			Timeout: 20 * time.Second,
			// ip-api's free HTTP endpoint drops idle keep-alive connections, so a reused
			// one yields "EOF" on the next POST. A fresh connection per request avoids that
			// (we only do ~30 req/min, so no pooling needed).
			Transport: &http.Transport{DisableKeepAlives: true},
		},
		url: batchURL,
		now: time.Now,
	}
}

// Resolved returns the lifetime count of proxy IPs actually geolocated (excludes empty
// markers). The checker reads this to fold geo progress into its single end-of-cycle log line,
// so the enricher itself stays silent (no separate geo log stream).
func (e *Enricher) Resolved() int64 { return e.resolved.Load() }

// Run loops until ctx is cancelled: pull a batch of un-enriched proxy IPs, look them up, and
// store. A cancelled ctx returns nil (graceful). It logs nothing on the happy path — progress
// surfaces via Resolved() in the checker's cycle-done line; only real errors are logged.
func (e *Enricher) Run(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	for {
		wait := e.cycle(ctx)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(wait):
		}
	}
}

// cycle processes one batch and returns how long to wait before the next. Only genuine
// store/query errors are logged; enrichment counts accumulate in e.resolved.
func (e *Enricher) cycle(ctx context.Context) time.Duration {
	ips, err := e.db.ProxyIPsMissingGeo(batchSize)
	if err != nil {
		log.Printf("geo: query missing IPs: %v", err)
		return idleWait
	}
	if len(ips) == 0 {
		return idleWait // every proxy IP already enriched
	}
	rows, retryAfter, err := e.lookup(ctx, ips)
	if err != nil {
		// Transient (e.g. ip-api closing the connection → EOF); the IPs stay queued and
		// retry next cycle. Silent — not worth a log line per occurrence.
		return pace
	}
	if len(rows) > 0 {
		now := e.now().UTC().Format("2006-01-02 15:04:05")
		if err := e.db.StoreGeo(rows, now); err != nil {
			log.Printf("geo: store: %v", err)
			return pace
		}
		var resolved int64
		for _, r := range rows {
			if r.CountryCode != "" {
				resolved++
			}
		}
		e.resolved.Add(resolved)
	}
	if retryAfter > 0 {
		return retryAfter // rate-limited — back off as the API asked
	}
	return pace
}

type apiResult struct {
	Status      string `json:"status"`
	Query       string `json:"query"`
	Country     string `json:"country"`
	CountryCode string `json:"countryCode"`
	ISP         string `json:"isp"`
	AS          string `json:"as"`
}

// lookup POSTs the IPs to the ip-api batch endpoint and returns the geo rows. A non-zero
// retryAfter means the API rate-limited us (429) and asks us to wait that long.
func (e *Enricher) lookup(ctx context.Context, ips []string) (rows []db.GeoRow, retryAfter time.Duration, err error) {
	body, _ := json.Marshal(ips)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.url, bytes.NewReader(body))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)
	resp, err := e.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusTooManyRequests {
		ttl := 5
		if v, e2 := strconv.Atoi(resp.Header.Get("X-Ttl")); e2 == nil && v > 0 {
			ttl = v
		}
		return nil, time.Duration(ttl+1) * time.Second, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("status %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxRespLen))
	if err != nil {
		return nil, 0, err
	}
	var results []apiResult
	if err := json.Unmarshal(data, &results); err != nil {
		return nil, 0, err
	}
	for _, r := range results {
		if r.Query == "" {
			continue
		}
		if r.Status != "success" {
			// ip-api couldn't geolocate this IP (private/reserved/invalid). Store an empty
			// marker row so it counts as "known" and isn't re-queried every cycle forever.
			// The dashboard aggregations skip empty country_code / asn.
			rows = append(rows, db.GeoRow{IP: r.Query})
			continue
		}
		rows = append(rows, db.GeoRow{
			IP:          r.Query,
			Country:     r.Country,
			CountryCode: r.CountryCode,
			ASN:         r.AS,
			ISP:         r.ISP,
		})
	}
	return rows, 0, nil
}
