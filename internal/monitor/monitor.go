package monitor

import (
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

type Snapshot struct {
	StartedAt        time.Time         `json:"started_at"`
	UptimeSeconds    int64             `json:"uptime_seconds"`
	SessionsStarted  uint64            `json:"sessions_started"`
	SessionsActive   int64             `json:"sessions_active"`
	SessionsComplete uint64            `json:"sessions_completed"`
	SessionsFailed   uint64            `json:"sessions_failed"`
	BytesSent        uint64            `json:"bytes_sent"`
	BytesReceived    uint64            `json:"bytes_received"`
	RouteDecisions   map[string]uint64 `json:"route_decisions"`
	FallbackResults  map[string]uint64 `json:"fallback_results"`
	LearnedRoutes    int               `json:"learned_routes"`
}

type Monitor struct {
	mu       sync.RWMutex
	started  time.Time
	snapshot Snapshot
	registry *prometheus.Registry

	sessionsStarted  prometheus.Counter
	sessionsActive   prometheus.Gauge
	sessionsFinished *prometheus.CounterVec
	bytes            *prometheus.CounterVec
	routes           *prometheus.CounterVec
	fallback         *prometheus.CounterVec
	dialDuration     *prometheus.HistogramVec
	sessionDuration  *prometheus.HistogramVec
	learnedRoutes    prometheus.Gauge
}

func New() *Monitor {
	registry := prometheus.NewRegistry()
	m := &Monitor{
		started:  time.Now(),
		registry: registry,
		sessionsStarted: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "socks_proxy_sessions_started_total",
			Help: "Total SOCKS5 sessions accepted by the proxy.",
		}),
		sessionsActive: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "socks_proxy_sessions_active",
			Help: "Current number of active SOCKS5 sessions.",
		}),
		sessionsFinished: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "socks_proxy_sessions_finished_total",
			Help: "Finished SOCKS5 sessions by result and egress.",
		}, []string{"result", "egress"}),
		bytes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "socks_proxy_bytes_total",
			Help: "Payload bytes forwarded by direction.",
		}, []string{"direction"}),
		routes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "socks_proxy_route_decisions_total",
			Help: "Successful route decisions by policy, egress and upstream.",
		}, []string{"policy", "egress", "upstream"}),
		fallback: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "socks_proxy_fallback_results_total",
			Help: "Fallback probe results by outcome and upstream.",
		}, []string{"outcome", "upstream"}),
		dialDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "socks_proxy_dial_duration_seconds",
			Help:    "Destination connection duration by egress and result.",
			Buckets: prometheus.DefBuckets,
		}, []string{"egress", "upstream", "result"}),
		sessionDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "socks_proxy_session_duration_seconds",
			Help:    "SOCKS5 session duration by egress.",
			Buckets: []float64{0.1, 0.5, 1, 3, 10, 30, 60, 300, 900, 3600},
		}, []string{"egress"}),
		learnedRoutes: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "socks_proxy_learned_routes",
			Help: "Current number of learned domain routes.",
		}),
	}
	m.snapshot.StartedAt = m.started
	m.snapshot.RouteDecisions = make(map[string]uint64)
	m.snapshot.FallbackResults = make(map[string]uint64)
	registry.MustRegister(
		m.sessionsStarted, m.sessionsActive, m.sessionsFinished, m.bytes,
		m.routes, m.fallback, m.dialDuration, m.sessionDuration, m.learnedRoutes,
		prometheus.NewGoCollector(), prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}),
	)
	return m
}

func (m *Monitor) Registry() *prometheus.Registry { return m.registry }

func (m *Monitor) SessionStarted() {
	m.mu.Lock()
	m.snapshot.SessionsStarted++
	m.snapshot.SessionsActive++
	m.mu.Unlock()
	m.sessionsStarted.Inc()
	m.sessionsActive.Inc()
}

func (m *Monitor) SessionFinished(tx, rx int, duration time.Duration, egress, result string) {
	if egress == "" {
		egress = "unknown"
	}
	m.mu.Lock()
	if m.snapshot.SessionsActive > 0 {
		m.snapshot.SessionsActive--
	}
	if result == "completed" {
		m.snapshot.SessionsComplete++
	} else {
		m.snapshot.SessionsFailed++
	}
	if tx > 0 {
		m.snapshot.BytesSent += uint64(tx)
	}
	if rx > 0 {
		m.snapshot.BytesReceived += uint64(rx)
	}
	m.mu.Unlock()
	m.sessionsActive.Dec()
	m.sessionsFinished.WithLabelValues(result, egress).Inc()
	m.bytes.WithLabelValues("client_to_target").Add(float64(tx))
	m.bytes.WithLabelValues("target_to_client").Add(float64(rx))
	m.sessionDuration.WithLabelValues(egress).Observe(duration.Seconds())
}

func (m *Monitor) RouteDecision(policy, egress, upstream string) {
	if upstream == "" {
		upstream = "none"
	}
	key := policy + "/" + egress + "/" + upstream
	m.mu.Lock()
	m.snapshot.RouteDecisions[key]++
	m.mu.Unlock()
	m.routes.WithLabelValues(policy, egress, upstream).Inc()
}

func (m *Monitor) FallbackResult(outcome, upstream string) {
	key := outcome + "/" + upstream
	m.mu.Lock()
	m.snapshot.FallbackResults[key]++
	m.mu.Unlock()
	m.fallback.WithLabelValues(outcome, upstream).Inc()
}

func (m *Monitor) ObserveDial(egress, upstream, result string, duration time.Duration) {
	if upstream == "" {
		upstream = "none"
	}
	m.dialDuration.WithLabelValues(egress, upstream, result).Observe(duration.Seconds())
}

func (m *Monitor) SetLearnedRoutes(count int) {
	m.mu.Lock()
	m.snapshot.LearnedRoutes = count
	m.mu.Unlock()
	m.learnedRoutes.Set(float64(count))
}

func (m *Monitor) Snapshot() Snapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := m.snapshot
	result.UptimeSeconds = int64(time.Since(m.started).Seconds())
	result.RouteDecisions = cloneMap(m.snapshot.RouteDecisions)
	result.FallbackResults = cloneMap(m.snapshot.FallbackResults)
	return result
}

func cloneMap(source map[string]uint64) map[string]uint64 {
	result := make(map[string]uint64, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}
