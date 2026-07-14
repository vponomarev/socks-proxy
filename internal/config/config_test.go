package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPolicyForStaticSocksWinsOverLearnedRoute(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "fixed.txt"), []byte(".example.com\n"), 0600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "proxy.yml")
	configYAML := []byte(`
proxy:
  port: 1080
upstreams:
  vpn:
    address: vpn:1080
  segment:
    address: segment:1080
detection:
  fallback-upstream: vpn
strategy:
  - name: fixed-segment
    list: fixed.txt
    egress: socks5
    upstream: segment
`)
	if err := os.WriteFile(configPath, configYAML, 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatal(err)
	}
	policy := cfg.PolicyFor("api.example.com", "vpn")
	if policy.Egress != "socks5" || policy.Upstream != "segment" || policy.Name != "fixed-segment" {
		t.Fatalf("PolicyFor() = %#v", policy)
	}
}

func TestPolicyForLearnedRouteReplacesDirect(t *testing.T) {
	cfg := &Config{
		Upstreams: map[string]Upstream{"vpn": {Address: "vpn:1080"}},
		Detection: Detection{FallbackUpstream: "vpn"},
		Default:   DefaultPolicy{Egress: "direct", DPI: "none"},
	}
	policy := cfg.PolicyFor("example.com", "vpn")
	if policy.Egress != "socks5" || policy.Upstream != "vpn" || policy.Name != "learned-domain" {
		t.Fatalf("PolicyFor() = %#v", policy)
	}
}

func TestPolicyCanDisableFallback(t *testing.T) {
	cfg := &Config{
		Upstreams: map[string]Upstream{"vpn": {Address: "vpn:1080"}},
		Detection: Detection{FallbackUpstream: "vpn"},
		Default:   DefaultPolicy{Egress: "direct", DPI: "none", Fallback: "none"},
	}
	policy := cfg.PolicyFor("example.com", "vpn")
	if policy.Egress != "direct" {
		t.Fatalf("PolicyFor() = %#v; want direct", policy)
	}
}

func TestAdminDefaultsAndLearnedTTL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "proxy.yml")
	data := []byte(`
proxy:
  port: 1080
admin:
  port: 9090
detection:
  learned-domain-ttl: 168h
`)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Admin.Address != "127.0.0.1" || cfg.Admin.Port != 9090 {
		t.Fatalf("admin config = %#v", cfg.Admin)
	}
	if cfg.Detection.LearnedTTL().Hours() != 168 {
		t.Fatalf("learned TTL = %v", cfg.Detection.LearnedTTL())
	}
}

func TestRejectsInvalidLearnedTTL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "proxy.yml")
	if err := os.WriteFile(path, []byte("detection:\n  learned-domain-ttl: forever\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("LoadConfig() accepted invalid learned-domain-ttl")
	}
}
