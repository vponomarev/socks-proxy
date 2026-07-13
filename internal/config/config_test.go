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
