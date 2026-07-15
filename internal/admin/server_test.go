package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vponomarev/socks-proxy/internal/config"
	"github.com/vponomarev/socks-proxy/internal/monitor"
	"github.com/vponomarev/socks-proxy/internal/routing"
	"github.com/vponomarev/socks-proxy/internal/upstream"
)

func TestDashboardStatusMetricsAndDelete(t *testing.T) {
	store, err := routing.Load(filepath.Join(t.TempDir(), "learned.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Add("blocked.example", "vpn", "test"); err != nil {
		t.Fatal(err)
	}
	metrics := monitor.New()
	metrics.SessionStarted()
	metrics.SessionFinished(12, 34, time.Second, "direct", "completed")
	upstreams := upstream.New(map[string]config.Upstream{"vpn": {Address: "vpn:1080"}}, config.UpstreamHealth{})
	reloadCalls := 0
	handler := NewHandler(
		metrics,
		store,
		func() *upstream.Manager { return upstreams },
		func() time.Duration { return 24 * time.Hour },
		func() int { return 100 },
		func() error { reloadCalls++; return nil },
	)

	dashboard := httptest.NewRecorder()
	handler.ServeHTTP(dashboard, httptest.NewRequest(http.MethodGet, "/", nil))
	if dashboard.Code != http.StatusOK || !strings.Contains(dashboard.Body.String(), "SOCKS Proxy") {
		t.Fatalf("dashboard = %d %q", dashboard.Code, dashboard.Body.String())
	}

	status := httptest.NewRecorder()
	handler.ServeHTTP(status, httptest.NewRequest(http.MethodGet, "/api/status", nil))
	var response statusResponse
	if err := json.NewDecoder(status.Body).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if response.Stats.SessionsStarted != 1 || len(response.Learned) != 1 || response.Learned[0].ExpiresAt.IsZero() || len(response.Upstreams) != 1 {
		t.Fatalf("status response = %#v", response)
	}

	metricResponse := httptest.NewRecorder()
	handler.ServeHTTP(metricResponse, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if !strings.Contains(metricResponse.Body.String(), "socks_proxy_sessions_started_total 1") {
		t.Fatalf("metrics missing session counter: %s", metricResponse.Body.String())
	}

	added := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/learned", strings.NewReader(`{"host":"manual.example","upstream":"vpn"}`))
	request.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(added, request)
	if added.Code != http.StatusOK {
		t.Fatalf("add learned = %d %q", added.Code, added.Body.String())
	}
	if entry, ok := store.Lookup("manual.example"); !ok || entry.Reason != "manual-api" {
		t.Fatalf("manual route = %#v, %v", entry, ok)
	}
	byeAdded := httptest.NewRecorder()
	byeRequest := httptest.NewRequest(http.MethodPost, "/api/learned", strings.NewReader(`{"host":"bye.example","route":"direct+bye"}`))
	handler.ServeHTTP(byeAdded, byeRequest)
	if byeAdded.Code != http.StatusOK {
		t.Fatalf("add bye route = %d %q", byeAdded.Code, byeAdded.Body.String())
	}
	if entry, ok := store.Lookup("bye.example"); !ok || entry.Route != routing.RouteBye || entry.Upstream != "" {
		t.Fatalf("manual bye route = %#v, %v", entry, ok)
	}

	unknown := httptest.NewRecorder()
	handler.ServeHTTP(unknown, httptest.NewRequest(http.MethodPost, "/api/learned", strings.NewReader(`{"host":"bad.example","upstream":"missing"}`)))
	if unknown.Code != http.StatusBadRequest {
		t.Fatalf("unknown upstream = %d; want %d", unknown.Code, http.StatusBadRequest)
	}

	deleted := httptest.NewRecorder()
	handler.ServeHTTP(deleted, httptest.NewRequest(http.MethodDelete, "/api/learned?host=blocked.example", nil))
	if deleted.Code != http.StatusOK {
		t.Fatalf("delete = %d %q", deleted.Code, deleted.Body.String())
	}
	if _, ok := store.Lookup("blocked.example"); ok {
		t.Fatal("route still exists after API delete")
	}

	reloaded := httptest.NewRecorder()
	handler.ServeHTTP(reloaded, httptest.NewRequest(http.MethodPost, "/api/reload", nil))
	if reloaded.Code != http.StatusOK || reloadCalls != 1 {
		t.Fatalf("reload = %d calls=%d body=%q", reloaded.Code, reloadCalls, reloaded.Body.String())
	}

	invalidReload := httptest.NewRecorder()
	handler.ServeHTTP(invalidReload, httptest.NewRequest(http.MethodGet, "/api/reload", nil))
	if invalidReload.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET reload = %d; want %d", invalidReload.Code, http.StatusMethodNotAllowed)
	}
}
