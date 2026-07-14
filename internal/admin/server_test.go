package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vponomarev/socks-proxy/internal/monitor"
	"github.com/vponomarev/socks-proxy/internal/routing"
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
	handler := NewHandler(metrics, store, 24*time.Hour)

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
	if response.Stats.SessionsStarted != 1 || len(response.Learned) != 1 || response.Learned[0].ExpiresAt.IsZero() {
		t.Fatalf("status response = %#v", response)
	}

	metricResponse := httptest.NewRecorder()
	handler.ServeHTTP(metricResponse, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if !strings.Contains(metricResponse.Body.String(), "socks_proxy_sessions_started_total 1") {
		t.Fatalf("metrics missing session counter: %s", metricResponse.Body.String())
	}

	deleted := httptest.NewRecorder()
	handler.ServeHTTP(deleted, httptest.NewRequest(http.MethodDelete, "/api/learned?host=blocked.example", nil))
	if deleted.Code != http.StatusOK {
		t.Fatalf("delete = %d %q", deleted.Code, deleted.Body.String())
	}
	if _, ok := store.Lookup("blocked.example"); ok {
		t.Fatal("route still exists after API delete")
	}
}
