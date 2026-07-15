package config

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"
)

func TestValidateFakeSNIMTU(t *testing.T) {
	for _, mtu := range []int{1, 575, 65536} {
		cfg := Config{FakeSni: FakeSni{MTU: mtu}, Default: DefaultPolicy{Egress: "direct", DPI: "none"}}
		if err := cfg.Validate(); err == nil {
			t.Fatalf("Validate accepted fake-sni MTU %d", mtu)
		}
	}
	for _, mtu := range []int{0, 576, 1500, 65535} {
		cfg := Config{FakeSni: FakeSni{MTU: mtu}, Default: DefaultPolicy{Egress: "direct", DPI: "none"}}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("Validate rejected fake-sni MTU %d: %v", mtu, err)
		}
	}
}

func TestPolicyForUsesPerDomainFakeSNI(t *testing.T) {
	actions := map[string]string{"fake-sni": "allowed.example", "ttl": "5"}
	cfg := Config{Strategy: []Strategy{{
		Name:   "fake",
		Egress: "direct",
		DPI:    "fake-sni",
		Params: map[string]string{"ttl": "7"},
		ListRecords: []DomainRecord{{
			Regexp:  mustPattern(t, "blocked.example"),
			Actions: &actions,
		}},
	}}}
	policy := cfg.PolicyFor("blocked.example", "")
	if got := policy.FakeSNI("global.example", "blocked.example"); got != "allowed.example" {
		t.Fatalf("FakeSNI() = %q", got)
	}
	if got := policy.TTL(9); got != 5 {
		t.Fatalf("TTL() = %d", got)
	}
}

func mustPattern(t *testing.T, value string) *regexp.Regexp {
	t.Helper()
	pattern, err := TemplateToRegex(value)
	if err != nil {
		t.Fatal(err)
	}
	return pattern
}

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
  shutdown-timeout: 20s
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
	if cfg.Proxy.GracefulTimeout() != 20*time.Second {
		t.Fatalf("shutdown timeout = %v", cfg.Proxy.GracefulTimeout())
	}
}

func TestProxyShutdownTimeoutDefaultsAndValidation(t *testing.T) {
	if got := (Proxy{}).GracefulTimeout(); got != 15*time.Second {
		t.Fatalf("default shutdown timeout = %v", got)
	}
	path := filepath.Join(t.TempDir(), "proxy.yml")
	if err := os.WriteFile(path, []byte("proxy:\n  shutdown-timeout: 0s\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("LoadConfig() accepted non-positive shutdown-timeout")
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

func TestUpstreamHealthDefaults(t *testing.T) {
	health := UpstreamHealth{Enabled: true}
	if health.CheckInterval() != 30*time.Second || health.CheckTimeout() != 5*time.Second || health.OpenCooldown() != 30*time.Second || health.Threshold() != 3 {
		t.Fatalf("health defaults = interval %v timeout %v cooldown %v threshold %d", health.CheckInterval(), health.CheckTimeout(), health.OpenCooldown(), health.Threshold())
	}
}

func TestRejectsInvalidUpstreamHealth(t *testing.T) {
	path := filepath.Join(t.TempDir(), "proxy.yml")
	data := []byte("upstream-health:\n  enabled: true\n  interval: 0s\n")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("LoadConfig() accepted zero health-check interval")
	}
}

func TestLearningFiltersLimitsAndBackoff(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "allow.txt"), []byte(".example.com\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "deny.txt"), []byte("private.example.com\n"), 0600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "proxy.yml")
	data := []byte("detection:\n  probe-failure-backoff: 2m\n  learned-max-entries: 42\n  learn-allow-list: allow.txt\n  learn-deny-list: deny.txt\n")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Detection.FailureBackoff() != 2*time.Minute || cfg.Detection.LearnedLimit() != 42 {
		t.Fatalf("learning settings = %v, %d", cfg.Detection.FailureBackoff(), cfg.Detection.LearnedLimit())
	}
	if allowed, _ := cfg.Detection.CanLearn("api.example.com"); !allowed {
		t.Fatal("allowed suffix was rejected")
	}
	if allowed, reason := cfg.Detection.CanLearn("private.example.com"); allowed || reason != "deny_list" {
		t.Fatalf("deny match = %v, %q", allowed, reason)
	}
	if allowed, reason := cfg.Detection.CanLearn("other.test"); allowed || reason != "not_in_allow_list" {
		t.Fatalf("allow miss = %v, %q", allowed, reason)
	}
	if (Detection{}).LearnedLimit() != 10000 || (Detection{}).FailureBackoff() != 5*time.Minute {
		t.Fatal("unexpected reliability defaults")
	}
}
