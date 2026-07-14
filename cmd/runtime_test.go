package main

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vponomarev/socks-proxy/internal/config"
	"github.com/vponomarev/socks-proxy/internal/upstream"
)

func TestValidateReload(t *testing.T) {
	base := &config.Config{
		Proxy:     config.Proxy{Address: "127.0.0.1", Port: 1080},
		Admin:     config.Admin{Address: "127.0.0.1", Port: 9090},
		FakeSni:   config.FakeSni{Interface: "eth0"},
		Detection: config.Detection{LearnedDomainsFile: "learned.yml"},
	}

	allowed := *base
	allowed.Proxy.ShutdownTimeout = "30s"
	allowed.Default.Egress = "direct"
	allowed.Upstreams = map[string]config.Upstream{"vpn": {Address: "vpn:1080"}}
	if err := validateReload(base, &allowed); err != nil {
		t.Fatalf("reloadable settings rejected: %v", err)
	}

	tests := []struct {
		name string
		edit func(*config.Config)
		want string
	}{
		{"proxy listener", func(c *config.Config) { c.Proxy.Port++ }, "proxy address and port"},
		{"admin listener", func(c *config.Config) { c.Admin.Port++ }, "admin listener"},
		{"capture interface", func(c *config.Config) { c.FakeSni.Interface = "eth1" }, "fake-sni interface"},
		{"learned store", func(c *config.Config) { c.Detection.LearnedDomainsFile = "other.yml" }, "learned-domains-file"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			next := *base
			tt.edit(&next)
			if err := validateReload(base, &next); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("validateReload() error = %v; want %q", err, tt.want)
			}
		})
	}
}

func TestSessionKeepsRuntimeSnapshot(t *testing.T) {
	previous := runtimeState.Load()
	t.Cleanup(func() { runtimeState.Store(previous) })

	firstConfig := &config.Config{Default: config.DefaultPolicy{Egress: "direct"}}
	first := &proxyRuntime{config: firstConfig, upstreams: upstream.New(nil, config.UpstreamHealth{})}
	runtimeState.Store(first)
	session := &Socks5{runtime: currentRuntime()}

	secondConfig := &config.Config{Default: config.DefaultPolicy{Egress: "socks5"}}
	runtimeState.Store(&proxyRuntime{config: secondConfig, upstreams: upstream.New(nil, config.UpstreamHealth{})})

	if session.sessionConfig() != firstConfig {
		t.Fatal("existing session did not retain its runtime snapshot")
	}
	if currentRuntime().config != secondConfig {
		t.Fatal("new sessions did not observe the replacement runtime")
	}
}

func TestWaitForWaitGroup(t *testing.T) {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		time.Sleep(10 * time.Millisecond)
		wg.Done()
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if !waitForWaitGroup(ctx, &wg) {
		t.Fatal("wait timed out before session completed")
	}

	wg.Add(1)
	short, stop := context.WithTimeout(context.Background(), time.Millisecond)
	defer stop()
	if waitForWaitGroup(short, &wg) {
		t.Fatal("wait completed while session was active")
	}
	wg.Done()
}
