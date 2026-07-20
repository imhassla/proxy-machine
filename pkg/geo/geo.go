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
	db     geoStore
	client *http.Client
	url    string // batch endpoint (overridable in tests)
	now    func() time.Time
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

// logInterval is the MINIMUM wall-clock time between progress summaries. A steady trickle of
// new proxy IPs (a few per cycle) must not print a line every idle transition, so we gate on
// elapsed time and only emit when something actually happened since the last line.
const logInterval = 5 * time.Minute

// cycleResult reports what one batch did, so Run can log periodic summaries instead of
// one line per batch.
type cycleResult struct {
	wait     time.Duration
	enriched int  // rows written (incl. empty markers)
	failed   bool // the batch lookup errored (e.g. transient EOF)
}

// Run loops until ctx is cancelled: pull a batch of un-enriched proxy IPs, look them up, and
// store. A cancelled ctx returns nil (graceful). Progress is logged as a time-gated summary
// (at most one line per logInterval), not per batch or per idle transition.
func (e *Enricher) Run(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	log.Printf("geo: enricher started (online lookup via ip-api.com, background)")
	var total, winEnriched, winErrors int
	lastLog := e.now()
	for {
		r := e.cycle(ctx)
		total += r.enriched
		winEnriched += r.enriched
		if r.failed {
			winErrors++
		}
		if (winEnriched > 0 || winErrors > 0) && e.now().Sub(lastLog) >= logInterval {
			log.Printf("geo: enriched %d IPs in the last %s (%d total; %d transient lookup errors)",
				winEnriched, logInterval, total, winErrors)
			winEnriched, winErrors = 0, 0
			lastLog = e.now()
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(r.wait):
		}
	}
}

// cycle processes one batch. It no longer logs per batch (Run summarizes); only genuine
// store/query errors are logged, since those are rare and actionable.
func (e *Enricher) cycle(ctx context.Context) cycleResult {
	ips, err := e.db.ProxyIPsMissingGeo(batchSize)
	if err != nil {
		log.Printf("geo: query missing IPs: %v", err)
		return cycleResult{wait: idleWait}
	}
	if len(ips) == 0 {
		return cycleResult{wait: idleWait} // every proxy IP already enriched
	}
	rows, retryAfter, err := e.lookup(ctx, ips)
	if err != nil {
		// Transient (e.g. ip-api closing the connection → EOF); the IPs stay queued and
		// retry next cycle. Counted in the summary, not logged per occurrence.
		return cycleResult{wait: pace, failed: true}
	}
	if len(rows) > 0 {
		now := e.now().UTC().Format("2006-01-02 15:04:05")
		if err := e.db.StoreGeo(rows, now); err != nil {
			log.Printf("geo: store: %v", err)
			return cycleResult{wait: pace}
		}
	}
	if retryAfter > 0 {
		return cycleResult{wait: retryAfter, enriched: len(rows)} // rate-limited — back off
	}
	return cycleResult{wait: pace, enriched: len(rows)}
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
