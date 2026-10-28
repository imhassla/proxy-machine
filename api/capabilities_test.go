package api

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCapabilitiesAndBoundedMetricLabels(t *testing.T) {
	s := New("127.0.0.1:0", nil, nil, nil)
	s.SetCapabilitiesProvider(func() any {
		return []map[string]any{{"target": "private-lab.example:8443", "stage": "connect_refused", "status": 403}}
	})
	w := httptest.NewRecorder()
	s.srv.Handler.ServeHTTP(w, httptest.NewRequest("GET", "/capabilities", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "connect_refused") {
		t.Fatal(w)
	}
	w = httptest.NewRecorder()
	s.srv.Handler.ServeHTTP(w, httptest.NewRequest("POST", "/capabilities", nil))
	if w.Code != 405 {
		t.Fatal(w.Code)
	}
	w = httptest.NewRecorder()
	s.srv.Handler.ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
	if strings.Contains(w.Body.String(), "private-lab.example") || !strings.Contains(w.Body.String(), `stage="connect_refused"`) {
		t.Fatal(w.Body.String())
	}
}
