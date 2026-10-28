package checker

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"proxymachine/config"
)

func TestHarvestBoundAndCircularProgressWithLargeBacklog(t *testing.T) {
	var body strings.Builder
	for i := 0; i < 90000; i++ {
		fmt.Fprintf(&body, "10.%d.%d.%d:8080\n", i>>16, (i>>8)&255, i&255)
	}
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body.String()) }))
	defer source.Close()
	cm := New(&config.Config{Workers: 2, MaxCandidates: 100, Timeout: time.Second}, nil)
	cm.ListURLs = []string{source.URL + "/http.txt"}
	a, _ := cm.gatherCandidates(context.Background())
	b, _ := cm.gatherCandidates(context.Background())
	if len(a) != 100 || len(b) != 100 {
		t.Fatalf("cap not enforced: %d %d", len(a), len(b))
	}
	seen := map[string]bool{}
	for _, job := range a {
		seen[job.addr] = true
	}
	for _, job := range b {
		if seen[job.addr] {
			t.Fatal("capped harvest repeated its first window", job.addr)
		}
	}
}

func TestRechecksProceedDuringBlockedListFetch(t *testing.T) {
	f := newCheckerFixture(t)
	defer f.cleanup()
	d := newTestDB(t)
	defer d.Close()
	old := time.Now().UTC().Add(-time.Hour).Format("2006-01-02 15:04:05")
	if err := d.StoreProxy("http", f.proxyAddr, 1, old); err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{}, 1)
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-r.Context().Done()
	}))
	defer source.Close()
	cm := New(&config.Config{Workers: 2, Timeout: 2 * time.Second, CheckInterval: 50 * time.Millisecond, MaxCandidates: 100}, d)
	cm.ListURLs = []string{source.URL + "/http.txt"}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- cm.Start(ctx) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("list fetch did not start")
	}
	deadline := time.Now().Add(time.Second)
	updated := false
	for time.Now().Before(deadline) {
		rows, err := d.GetProxyRows("http")
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) == 1 && rows[0].LastChecked != old {
			updated = true
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("checker did not drain on cancellation")
	}
	if !updated {
		t.Fatal("stored proxy recheck waited for blocked public list fetch")
	}
}

func TestValidationBudgetReservesRecheckCapacity(t *testing.T) {
	g := newValidationGate(5)
	g.reserve()
	var releases []func()
	for i := 0; i < 4; i++ {
		r, e := g.acquire(context.Background(), false)
		if e != nil {
			t.Fatal(e)
		}
		releases = append(releases, r)
	}
	defer func() {
		for _, r := range releases {
			r()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if r, err := g.acquire(ctx, false); err == nil {
		r()
		t.Fatal("bulk work consumed reserved capacity")
	}
	r, err := g.acquire(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	defer r()
	if g.active != 5 {
		t.Fatal(g.active)
	}
}
