package geo

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"proxymachine/db"
)

// fakeStore records what StoreGeo received and hands out a fixed missing-IP queue.
type fakeStore struct {
	missing []string
	stored  []db.GeoRow
}

func (f *fakeStore) ProxyIPsMissingGeo(limit int) ([]string, error)  { return f.missing, nil }
func (f *fakeStore) StoreGeo(rows []db.GeoRow, updated string) error { f.stored = rows; return nil }

func TestEnricherLookupAndStore(t *testing.T) {
	// Fake ip-api batch endpoint: echoes geo for the requested IPs, marks a private one failed.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var ips []string
		_ = json.NewDecoder(r.Body).Decode(&ips)
		out := make([]map[string]any, 0, len(ips))
		for _, ip := range ips {
			if ip == "10.0.0.1" {
				out = append(out, map[string]any{"status": "fail", "query": ip})
				continue
			}
			out = append(out, map[string]any{
				"status": "success", "query": ip, "country": "United States",
				"countryCode": "US", "isp": "ExampleISP", "as": "AS64500 Example",
			})
		}
		_ = json.NewEncoder(w).Encode(out)
	}))
	defer srv.Close()

	store := &fakeStore{missing: []string{"1.2.3.4", "10.0.0.1"}}
	e := New(store)
	e.url = srv.URL
	e.now = func() time.Time { return time.Unix(0, 0) }

	wait := e.cycle(context.Background())
	if wait != pace {
		t.Fatalf("cycle wait = %v, want pace %v", wait, pace)
	}
	if got := e.Resolved(); got != 1 {
		t.Fatalf("Resolved() = %d, want 1 (only 1.2.3.4 geolocated; 10.0.0.1 is an empty marker)", got)
	}
	// Both IPs are stored: the resolvable one with geo, the un-geolocatable one as an empty
	// marker (so it isn't re-queried every cycle forever).
	if len(store.stored) != 2 {
		t.Fatalf("stored %d rows, want 2 (resolvable + empty marker): %+v", len(store.stored), store.stored)
	}
	byIP := map[string]db.GeoRow{}
	for _, g := range store.stored {
		byIP[g.IP] = g
	}
	g := byIP["1.2.3.4"]
	if g.CountryCode != "US" || g.ASN != "AS64500 Example" || g.ISP != "ExampleISP" {
		t.Fatalf("geo row wrong: %+v", g)
	}
	if m, ok := byIP["10.0.0.1"]; !ok || m.CountryCode != "" || m.ASN != "" {
		t.Fatalf("marker row for un-geolocatable IP wrong: %+v (present=%v)", m, ok)
	}
}

func TestEnricherRateLimited(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Ttl", "7")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()
	e := New(&fakeStore{missing: []string{"1.2.3.4"}})
	e.url = srv.URL
	_, retry, err := e.lookup(context.Background(), []string{"1.2.3.4"})
	if err != nil {
		t.Fatal(err)
	}
	if retry < 7*time.Second {
		t.Fatalf("retryAfter = %v, want >= 7s (from X-Ttl)", retry)
	}
}
