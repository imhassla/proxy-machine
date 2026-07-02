package relay

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"proxymachine/db"
)

type fakeManager struct {
	cache map[string][]string
}

func (f *fakeManager) Cache() map[string][]string {
	return f.cache
}

type fakeDB struct {
	data map[string][]string
	err  error
}

func (f *fakeDB) GetProxiesByType(proxyType string) ([]string, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.data[proxyType], nil
}

func TestSelectorRefresh_CombinesCacheAndDB(t *testing.T) {
	mgr := &fakeManager{cache: map[string][]string{
		"http":    {"cache1:8080"},
		"https":   {"cache2:8443"},
		"unknown": {"ignored:1234"},
	}}
	dbase := &fakeDB{data: map[string][]string{
		"http":  {"cache1:8080", "db1:8080"},
		"https": {"db2:8443"},
	}}

	s := newSelector(mgr, dbase)
	if err := s.refresh(context.Background()); err != nil {
		t.Fatalf("refresh: %v", err)
	}

	taken := make(map[string]bool)
	for i := 0; i < 5; i++ {
		got, _, err := s.next(context.Background())
		if err != nil {
			t.Fatalf("next: %v", err)
		}
		taken[got] = true
	}

	// Candidates carry their scheme (type://addr) so the transport dials the right way.
	for _, want := range []string{"http://cache1:8080", "https://cache2:8443", "http://db1:8080", "https://db2:8443"} {
		if !taken[want] {
			t.Errorf("expected candidate %s to be selectable, got %v", want, taken)
		}
	}
	if taken["http://ignored:1234"] || taken["ignored:1234"] {
		t.Errorf("unknown proxy type should not be included")
	}
}

func TestSelectorRefresh_NoProxies_ReturnsError(t *testing.T) {
	s := newSelector(&fakeManager{}, &fakeDB{})
	if err := s.refresh(context.Background()); !errors.Is(err, ErrNoProxyAvailable) {
		t.Fatalf("expected ErrNoProxyAvailable, got %v", err)
	}
}

func TestSelectorNext_RotatesRoundRobin(t *testing.T) {
	mgr := &fakeManager{cache: map[string][]string{
		"http": {"a:1", "b:2", "c:3"},
	}}
	s := newSelector(mgr, nil)
	_ = s.refresh(context.Background())

	var got []string
	for i := 0; i < 6; i++ {
		addr, _, _ := s.next(context.Background())
		got = append(got, addr)
	}

	want := []string{"http://a:1", "http://b:2", "http://c:3", "http://a:1", "http://b:2", "http://c:3"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("index %d: want %s, got %s", i, want[i], got[i])
		}
	}
}

func TestSelectorNext_BeforeRefresh_ReturnsError(t *testing.T) {
	s := newSelector(&fakeManager{}, nil)
	_, _, err := s.next(context.Background())
	if !errors.Is(err, ErrNoProxyAvailable) {
		t.Fatalf("expected ErrNoProxyAvailable, got %v", err)
	}
}

func TestSelectorRefresh_DedupesCacheAndDB(t *testing.T) {
	mgr := &fakeManager{cache: map[string][]string{
		"http": {"dup:8080", "onlyCache:8080"},
	}}
	dbase := &fakeDB{data: map[string][]string{
		"http": {"dup:8080", "onlyDB:8080"},
	}}
	s := newSelector(mgr, dbase)
	_ = s.refresh(context.Background())

	seen := make(map[string]int)
	for i := 0; i < 4; i++ {
		addr, _, _ := s.next(context.Background())
		seen[addr]++
	}

	if seen["http://dup:8080"] != 2 {
		t.Fatalf("expected duplicate to appear once per round, got %d", seen["http://dup:8080"])
	}
	want := map[string]int{"http://dup:8080": 2, "http://onlyCache:8080": 1, "http://onlyDB:8080": 1}
	for k, v := range want {
		if seen[k] != v {
			t.Errorf("%s: want %d, got %d", k, v, seen[k])
		}
	}
}

func TestSelectorUsesRealDB(t *testing.T) {
	dbase, err := db.OpenInMemory()
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer dbase.Close()

	if err := dbase.Init(); err != nil {
		t.Fatalf("init db: %v", err)
	}

	for _, p := range []string{"real1:8080", "real2:8080"} {
		if err := dbase.StoreProxy("http", p, 0, ""); err != nil {
			t.Fatalf("store %s: %v", p, err)
		}
	}

	mgr := &fakeManager{cache: map[string][]string{}}
	s := newSelector(mgr, dbase)
	if err := s.refresh(context.Background()); err != nil {
		t.Fatalf("refresh: %v", err)
	}

	addr, _, err := s.next(context.Background())
	if err != nil {
		t.Fatalf("next: %v", err)
	}

	found := false
	for _, p := range []string{"http://real1:8080", "http://real2:8080"} {
		if addr == p {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected a real db proxy, got %s", addr)
	}
	_ = fmt.Sprintf("selected %s", addr)
}
