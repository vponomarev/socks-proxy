package admin

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/vponomarev/socks-proxy/internal/config"
	"github.com/vponomarev/socks-proxy/internal/monitor"
	"github.com/vponomarev/socks-proxy/internal/routing"
	"github.com/vponomarev/socks-proxy/internal/upstream"
)

type API struct {
	metrics          *monitor.Monitor
	routes           *routing.Store
	upstreamProvider func() *upstream.Manager
	ttlProvider      func() time.Duration
	limitProvider    func() int
	reload           func() error
}

type learnedView struct {
	routing.LearnedDomain
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}

type statusResponse struct {
	Stats     monitor.Snapshot `json:"stats"`
	Learned   []learnedView    `json:"learned"`
	Upstreams []upstream.State `json:"upstreams"`
}

func NewHandler(metrics *monitor.Monitor, routes *routing.Store, upstreamProvider func() *upstream.Manager, ttlProvider func() time.Duration, limitProvider func() int, reload func() error) http.Handler {
	api := &API{metrics: metrics, routes: routes, upstreamProvider: upstreamProvider, ttlProvider: ttlProvider, limitProvider: limitProvider, reload: reload}
	mux := http.NewServeMux()
	mux.HandleFunc("/", api.dashboard)
	mux.HandleFunc("/healthz", api.health)
	mux.HandleFunc("/api/status", api.status)
	mux.HandleFunc("/api/learned", api.learned)
	mux.HandleFunc("/api/upstreams", api.upstreamStates)
	mux.HandleFunc("/api/reload", api.reloadConfig)
	mux.Handle("/metrics", promhttp.HandlerFor(metrics.Registry(), promhttp.HandlerOpts{}))
	return mux
}

func Start(cfg config.Admin, metrics *monitor.Monitor, routes *routing.Store, upstreamProvider func() *upstream.Manager, ttlProvider func() time.Duration, limitProvider func() int, reload func() error) (*http.Server, error) {
	address := net.JoinHostPort(cfg.Address, fmt.Sprintf("%d", cfg.Port))
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, err
	}
	server := &http.Server{
		Addr:              address,
		Handler:           NewHandler(metrics, routes, upstreamProvider, ttlProvider, limitProvider, reload),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			log.Printf("Admin server stopped: %v", err)
		}
	}()
	return server, nil
}

func (a *API) reloadConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a.reload == nil {
		http.Error(w, "configuration reload is unavailable", http.StatusNotImplemented)
		return
	}
	if err := a.reload(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "reloaded", "reloaded_at": time.Now()})
}

func (a *API) dashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(dashboardHTML))
}

func (a *API) health(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (a *API) status(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	entries := a.views()
	a.metrics.SetLearnedRoutes(len(entries))
	writeJSON(w, http.StatusOK, statusResponse{Stats: a.metrics.Snapshot(), Learned: entries, Upstreams: a.upstreamViews()})
}

func (a *API) upstreamStates(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, a.upstreamViews())
}

func (a *API) upstreamViews() []upstream.State {
	manager := a.currentUpstreams()
	if manager == nil {
		return []upstream.State{}
	}
	return manager.States()
}

func (a *API) currentUpstreams() *upstream.Manager {
	if a.upstreamProvider == nil {
		return nil
	}
	return a.upstreamProvider()
}

func (a *API) learned(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, a.views())
	case http.MethodPost:
		a.addLearned(w, r)
	case http.MethodDelete:
		host := r.URL.Query().Get("host")
		if host == "" {
			http.Error(w, "host query parameter is required", http.StatusBadRequest)
			return
		}
		deleted, err := a.routes.Delete(host)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if !deleted {
			http.Error(w, "learned route not found", http.StatusNotFound)
			return
		}
		a.metrics.SetLearnedRoutes(len(a.routes.Entries()))
		writeJSON(w, http.StatusOK, map[string]any{"deleted": true, "host": host})
	default:
		w.Header().Set("Allow", "GET, POST, DELETE")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (a *API) addLearned(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Host     string `json:"host"`
		Upstream string `json:"upstream"`
		Reason   string `json:"reason"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		http.Error(w, "invalid JSON body: "+err.Error(), http.StatusBadRequest)
		return
	}
	manager := a.currentUpstreams()
	if manager == nil {
		http.Error(w, "upstream manager is unavailable", http.StatusServiceUnavailable)
		return
	}
	if _, exists := manager.State(request.Upstream); !exists {
		http.Error(w, "unknown upstream", http.StatusBadRequest)
		return
	}
	reason := request.Reason
	if reason == "" {
		reason = "manual-api"
	}
	limit := 0
	if a.limitProvider != nil {
		limit = a.limitProvider()
	}
	added, evicted, err := a.routes.AddWithLimit(request.Host, request.Upstream, reason, limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	a.metrics.SetLearnedRoutes(len(a.routes.Entries()))
	writeJSON(w, http.StatusOK, map[string]any{"added": added, "host": request.Host, "evicted": evicted})
}

func (a *API) views() []learnedView {
	entries := a.routes.Entries()
	result := make([]learnedView, 0, len(entries))
	for _, entry := range entries {
		view := learnedView{LearnedDomain: entry}
		ttl := time.Duration(0)
		if a.ttlProvider != nil {
			ttl = a.ttlProvider()
		}
		if ttl > 0 {
			view.ExpiresAt = entry.LearnedAt.Add(ttl)
		}
		result = append(result, view)
	}
	return result
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

const dashboardHTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SOCKS Proxy</title><style>
:root{color-scheme:dark;font:14px system-ui;background:#101418;color:#e6edf3}body{max-width:1200px;margin:32px auto;padding:0 20px}h1{font-size:24px}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px}.card,table{background:#182028;border:1px solid #303b45;border-radius:8px}.card{padding:16px}.value{font-size:24px;font-weight:650;margin-top:6px}table{width:100%;border-collapse:collapse;margin-top:20px;overflow:hidden}th,td{padding:10px;text-align:left;border-bottom:1px solid #303b45}th{color:#9fb0bf}button{background:#b42318;color:white;border:0;border-radius:5px;padding:6px 10px;cursor:pointer}a{color:#58a6ff}.muted{color:#9fb0bf}</style></head>
<body><h1>SOCKS Proxy</h1><p class="muted">Live status · refreshes every 5 seconds · <a href="/metrics">Prometheus metrics</a> · <button id="reload">Reload config</button></p>
<div class="cards" id="cards"></div><h2>Upstreams</h2><table><thead><tr><th>Name</th><th>Address</th><th>Health</th><th>Circuit</th><th>Failures</th><th>Last check</th><th>Error</th></tr></thead><tbody id="upstreams"></tbody></table>
<h2>Routing</h2><table><thead><tr><th>Policy / egress / upstream</th><th>Connections</th></tr></thead><tbody id="decisions"></tbody></table>
<h2>Fallback</h2><table><thead><tr><th>Outcome / upstream</th><th>Events</th></tr></thead><tbody id="fallback"></tbody></table>
<h2>Learned domains</h2><table><thead><tr><th>Host</th><th>Upstream</th><th>Learned</th><th>Last used</th><th>Hits</th><th></th></tr></thead><tbody id="routes"></tbody></table>
<script>
const fmt=n=>Number(n||0).toLocaleString(); const age=s=>s?new Date(s).toLocaleString():'—'; const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
async function removeHost(host){if(!confirm('Delete learned route '+host+'?'))return;await fetch('/api/learned?host='+encodeURIComponent(host),{method:'DELETE'});load()}
async function reloadConfig(){const r=await fetch('/api/reload',{method:'POST'});if(!r.ok)alert(await r.text());else load()}
async function load(){const r=await fetch('/api/status');const d=await r.json(),s=d.stats;
const cards=[['Active',s.sessions_active],['Sessions',s.sessions_started],['Completed',s.sessions_completed],['Failed',s.sessions_failed],['Sent bytes',s.bytes_sent],['Received bytes',s.bytes_received],['Learned',s.learned_routes],['Uptime seconds',s.uptime_seconds]];
document.querySelector('#cards').innerHTML=cards.map(x=>'<div class="card"><div class="muted">'+x[0]+'</div><div class="value">'+fmt(x[1])+'</div></div>').join('');
document.querySelector('#upstreams').innerHTML=(d.upstreams||[]).map(x=>'<tr><td>'+esc(x.name)+'</td><td>'+esc(x.address)+'</td><td>'+esc(x.health)+'</td><td>'+esc(x.circuit)+'</td><td>'+fmt(x.consecutive_failures)+'</td><td>'+age(x.last_check)+'</td><td>'+esc(x.last_error)+'</td></tr>').join('');
const rows=o=>Object.entries(o||{}).sort().map(x=>'<tr><td>'+esc(x[0])+'</td><td>'+fmt(x[1])+'</td></tr>').join('');document.querySelector('#decisions').innerHTML=rows(s.route_decisions);document.querySelector('#fallback').innerHTML=rows(s.fallback_results);
document.querySelector('#routes').innerHTML=d.learned.map(x=>'<tr><td>'+esc(x.host)+'</td><td>'+esc(x.upstream)+'</td><td>'+age(x.learned_at)+'</td><td>'+age(x.last_used_at)+'</td><td>'+fmt(x.hit_count)+'</td><td><button data-host="'+encodeURIComponent(x.host)+'">Delete</button></td></tr>').join('');
document.querySelectorAll('button[data-host]').forEach(b=>b.onclick=()=>removeHost(decodeURIComponent(b.dataset.host)));}
document.querySelector('#reload').onclick=reloadConfig;
load();setInterval(load,5000);
</script></body></html>`
