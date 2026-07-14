package upstream

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/vponomarev/socks-proxy/internal/config"
	"github.com/vponomarev/socks-proxy/internal/socksclient"
)

var ErrCircuitOpen = errors.New("SOCKS5 upstream circuit is open")

type State struct {
	Name                string    `json:"name"`
	Address             string    `json:"address"`
	Health              string    `json:"health"`
	Circuit             string    `json:"circuit"`
	ConsecutiveFailures int       `json:"consecutive_failures"`
	LastCheck           time.Time `json:"last_check,omitempty"`
	LastSuccess         time.Time `json:"last_success,omitempty"`
	OpenUntil           time.Time `json:"open_until,omitempty"`
	LastError           string    `json:"last_error,omitempty"`
}

type managedState struct {
	State
	halfOpenInFlight bool
}

type checkFunc func(context.Context, config.Upstream) error

type Manager struct {
	mu        sync.Mutex
	config    config.UpstreamHealth
	upstreams map[string]config.Upstream
	states    map[string]*managedState
	now       func() time.Time
	check     checkFunc
}

func New(upstreams map[string]config.Upstream, health config.UpstreamHealth) *Manager {
	m := &Manager{
		config:    health,
		upstreams: make(map[string]config.Upstream, len(upstreams)),
		states:    make(map[string]*managedState, len(upstreams)),
		now:       time.Now,
		check:     socksclient.Check,
	}
	for name, upstream := range upstreams {
		m.upstreams[name] = upstream
		m.states[name] = &managedState{State: State{
			Name: name, Address: upstream.Address, Health: "unknown", Circuit: "closed",
		}}
	}
	return m
}

func (m *Manager) Enabled() bool { return m != nil && m.config.Enabled }

// Allow applies the circuit breaker to a real upstream request. After the
// cooldown, exactly one request is admitted as a half-open probe.
func (m *Manager) Allow(name string) bool {
	if m == nil || !m.config.Enabled {
		return true
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	state, ok := m.states[name]
	if !ok {
		return false
	}
	if state.Circuit != "open" && state.Circuit != "half-open" {
		return true
	}
	now := m.now()
	if state.Circuit == "open" && now.Before(state.OpenUntil) {
		return false
	}
	if state.halfOpenInFlight {
		return false
	}
	state.Circuit = "half-open"
	state.halfOpenInFlight = true
	return true
}

// Record updates health and breaker state after an active check or real dial.
func (m *Manager) Record(name string, err error) State {
	if m == nil {
		return State{Name: name, Health: "unknown", Circuit: "closed"}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	state, ok := m.states[name]
	if !ok {
		return State{Name: name, Health: "unknown", Circuit: "closed"}
	}
	now := m.now()
	state.LastCheck = now
	state.halfOpenInFlight = false
	if err == nil {
		state.Health = "healthy"
		state.Circuit = "closed"
		state.ConsecutiveFailures = 0
		state.LastSuccess = now
		state.OpenUntil = time.Time{}
		state.LastError = ""
		return state.State
	}
	state.Health = "unhealthy"
	state.ConsecutiveFailures++
	state.LastError = err.Error()
	if m.config.Enabled && (state.Circuit == "half-open" || state.ConsecutiveFailures >= m.config.Threshold()) {
		state.Circuit = "open"
		state.OpenUntil = now.Add(m.config.OpenCooldown())
	}
	return state.State
}

func (m *Manager) State(name string) (State, bool) {
	if m == nil {
		return State{}, false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	state, ok := m.states[name]
	if !ok {
		return State{}, false
	}
	return state.State, true
}

func (m *Manager) States() []State {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]State, 0, len(m.states))
	for _, state := range m.states {
		result = append(result, state.State)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result
}

// CheckAll actively verifies each configured upstream. Checks bypass an open
// circuit so a recovered proxy can close the breaker before cooldown elapses.
func (m *Manager) CheckAll(ctx context.Context) []State {
	if m == nil || !m.config.Enabled {
		return m.States()
	}
	names := make([]string, 0, len(m.upstreams))
	for name := range m.upstreams {
		names = append(names, name)
	}
	sort.Strings(names)
	result := make([]State, 0, len(names))
	for _, name := range names {
		checkCtx, cancel := context.WithTimeout(ctx, m.config.CheckTimeout())
		err := m.check(checkCtx, m.upstreams[name])
		cancel()
		result = append(result, m.Record(name, err))
	}
	return result
}
