package main

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/vponomarev/socks-proxy/internal/config"
	"github.com/vponomarev/socks-proxy/internal/upstream"
)

// proxyRuntime is immutable after publication. Each accepted SOCKS session
// keeps one snapshot, so a reload affects new sessions without racing or
// changing policy midway through an existing connection.
type proxyRuntime struct {
	config    *config.Config
	upstreams *upstream.Manager
}

var (
	runtimeState atomic.Pointer[proxyRuntime]
	reloadMu     sync.Mutex
	healthMu     sync.Mutex
	healthCancel context.CancelFunc
)

func currentRuntime() *proxyRuntime {
	if runtime := runtimeState.Load(); runtime != nil {
		return runtime
	}
	return &proxyRuntime{config: Cfg, upstreams: UpstreamManager}
}

func installRuntime(parent context.Context, cfg *config.Config) *proxyRuntime {
	runtime := &proxyRuntime{
		config:    cfg,
		upstreams: upstream.New(cfg.Upstreams, cfg.UpstreamHealth),
	}
	runtimeState.Store(runtime)
	if ProxyMetrics != nil {
		for _, state := range runtime.upstreams.States() {
			ProxyMetrics.SetUpstreamState(state.Name, state.Health, state.Circuit)
		}
	}

	healthMu.Lock()
	if healthCancel != nil {
		healthCancel()
	}
	healthCtx, cancel := context.WithCancel(parent)
	healthCancel = cancel
	healthMu.Unlock()
	if runtime.upstreams.Enabled() {
		go monitorUpstreamHealth(healthCtx, runtime)
	}
	return runtime
}

func stopRuntimeHealth() {
	healthMu.Lock()
	defer healthMu.Unlock()
	if healthCancel != nil {
		healthCancel()
		healthCancel = nil
	}
}

func reloadRuntime(parent context.Context, path string) error {
	reloadMu.Lock()
	defer reloadMu.Unlock()

	next, err := config.LoadConfig(path)
	if err != nil {
		return fmt.Errorf("load configuration: %w", err)
	}
	current := currentRuntime()
	if current == nil || current.config == nil {
		return fmt.Errorf("proxy runtime is not initialized")
	}
	if err := validateReload(current.config, next); err != nil {
		return err
	}
	if LearnedRoutes != nil {
		removed, err := LearnedRoutes.PruneToLimit(next.Detection.LearnedLimit())
		if err != nil {
			return fmt.Errorf("enforce learned domain limit: %w", err)
		}
		if removed > 0 && ProxyMetrics != nil {
			ProxyMetrics.SetLearnedRoutes(len(LearnedRoutes.Entries()))
		}
	}
	installRuntime(parent, next)
	return nil
}

// Listener, admin, capture, and learned-store locations require resource
// replacement and therefore remain restart-only settings.
func validateReload(current, next *config.Config) error {
	if current.Proxy.Address != next.Proxy.Address || current.Proxy.Port != next.Proxy.Port {
		return fmt.Errorf("proxy address and port require restart")
	}
	if current.Admin != next.Admin {
		return fmt.Errorf("admin listener settings require restart")
	}
	if current.FakeSni.Interface != next.FakeSni.Interface {
		return fmt.Errorf("fake-sni interface requires restart")
	}
	if current.Detection.LearnedDomainsFile != next.Detection.LearnedDomainsFile {
		return fmt.Errorf("learned-domains-file requires restart")
	}
	return nil
}

func (s *Socks5) runtimeSnapshot() *proxyRuntime {
	if s.runtime != nil {
		return s.runtime
	}
	return currentRuntime()
}

func (s *Socks5) sessionConfig() *config.Config {
	return s.runtimeSnapshot().config
}
