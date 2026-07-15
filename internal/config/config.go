package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v2"
)

type Strategy struct {
	Name        string            `yaml:"name"`
	List        string            `yaml:"list"`
	Action      string            `yaml:"action"`
	Egress      string            `yaml:"egress"`
	DPI         string            `yaml:"dpi"`
	Upstream    string            `yaml:"upstream"`
	Fallback    string            `yaml:"fallback"`
	Params      map[string]string `yaml:"params"`
	ListRecords []DomainRecord    `yaml:"-"`
}

type Proxy struct {
	Address         string `yaml:"address"`
	Port            int    `yaml:"port"`
	ShutdownTimeout string `yaml:"shutdown-timeout"`
}

func (p Proxy) GracefulTimeout() time.Duration {
	return parseDuration(p.ShutdownTimeout, 15*time.Second)
}

type FakeSni struct {
	Interface string `yaml:"interface"`
	Ttl       int    `yaml:"ttl"`
	MTU       int    `yaml:"mtu"`
	Decoy     string `yaml:"decoy"`
}

// Bye configures application-level ClientHello splitting. It deliberately
// uses ordinary TCP sockets so it works on Windows and Linux without packet
// capture privileges.
type Bye struct {
	Mode        string `yaml:"mode"`
	SplitOffset int    `yaml:"split-offset"`
	Delay       string `yaml:"delay"`
}

func (b Bye) SplitMode() string {
	if b.Mode == "" {
		return "tcp-split"
	}
	return strings.ToLower(b.Mode)
}

func (b Bye) Offset() int {
	if b.SplitOffset <= 0 {
		return 3
	}
	return b.SplitOffset
}

func (b Bye) SplitDelay() time.Duration {
	return parseDuration(b.Delay, 15*time.Millisecond)
}

type Upstream struct {
	Address        string `yaml:"address"`
	Username       string `yaml:"username"`
	Password       string `yaml:"password"`
	ConnectTimeout string `yaml:"connect-timeout"`
}

func (u Upstream) Timeout() time.Duration {
	return parseDuration(u.ConnectTimeout, 5*time.Second)
}

type Detection struct {
	FirstResponseTimeout string         `yaml:"first-response-timeout"`
	ProbeTimeout         string         `yaml:"probe-timeout"`
	ProbeFailureBackoff  string         `yaml:"probe-failure-backoff"`
	FallbackUpstream     string         `yaml:"fallback-upstream"`
	LearnedDomainsFile   string         `yaml:"learned-domains-file"`
	LearnedDomainTTL     string         `yaml:"learned-domain-ttl"`
	LearnedMaxEntries    int            `yaml:"learned-max-entries"`
	LearnAllowList       string         `yaml:"learn-allow-list"`
	LearnDenyList        string         `yaml:"learn-deny-list"`
	LearnAllowRecords    []DomainRecord `yaml:"-"`
	LearnDenyRecords     []DomainRecord `yaml:"-"`
}

func (d Detection) ResponseTimeout() time.Duration {
	return parseDuration(d.FirstResponseTimeout, 3*time.Second)
}

func (d Detection) FallbackProbeTimeout() time.Duration {
	return parseDuration(d.ProbeTimeout, 5*time.Second)
}

func (d Detection) FailureBackoff() time.Duration {
	return parseDuration(d.ProbeFailureBackoff, 5*time.Minute)
}

func (d Detection) LearnedTTL() time.Duration {
	return parseDuration(d.LearnedDomainTTL, 0)
}

func (d Detection) LearnedLimit() int {
	if d.LearnedMaxEntries == 0 {
		return 10000
	}
	return d.LearnedMaxEntries
}

// CanLearn applies the optional automatic-learning filters. A deny match
// always wins; when an allow list is configured, unmatched hosts are denied.
func (d Detection) CanLearn(host string) (bool, string) {
	if recordsMatch(d.LearnDenyRecords, host) {
		return false, "deny_list"
	}
	if d.LearnAllowList != "" && !recordsMatch(d.LearnAllowRecords, host) {
		return false, "not_in_allow_list"
	}
	return true, ""
}

type Admin struct {
	Address string `yaml:"address"`
	Port    int    `yaml:"port"`
}

type UpstreamHealth struct {
	Enabled          bool   `yaml:"enabled"`
	Interval         string `yaml:"interval"`
	Timeout          string `yaml:"timeout"`
	FailureThreshold int    `yaml:"failure-threshold"`
	Cooldown         string `yaml:"cooldown"`
}

func (h UpstreamHealth) CheckInterval() time.Duration {
	return parseDuration(h.Interval, 30*time.Second)
}

func (h UpstreamHealth) CheckTimeout() time.Duration {
	return parseDuration(h.Timeout, 5*time.Second)
}

func (h UpstreamHealth) OpenCooldown() time.Duration {
	return parseDuration(h.Cooldown, 30*time.Second)
}

func (h UpstreamHealth) Threshold() int {
	if h.FailureThreshold <= 0 {
		return 3
	}
	return h.FailureThreshold
}

func (a Admin) Enabled() bool {
	return a.Port > 0
}

type DefaultPolicy struct {
	Egress   string `yaml:"egress"`
	DPI      string `yaml:"dpi"`
	Upstream string `yaml:"upstream"`
	Fallback string `yaml:"fallback"`
}

type ResolvedPolicy struct {
	Name     string
	Egress   string
	DPI      string
	Upstream string
	Fallback string
	Params   map[string]string
}

type Config struct {
	Proxy          Proxy               `yaml:"proxy"`
	Admin          Admin               `yaml:"admin"`
	FakeSni        FakeSni             `yaml:"fake-sni"`
	Bye            Bye                 `yaml:"bye"`
	Upstreams      map[string]Upstream `yaml:"upstreams"`
	UpstreamHealth UpstreamHealth      `yaml:"upstream-health"`
	Detection      Detection           `yaml:"detection"`
	Default        DefaultPolicy       `yaml:"default"`
	Strategy       []Strategy          `yaml:"strategy"`
}

func LoadConfig(path string) (config *Config, err error) {
	// Read the file
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// Create a new Config instance
	config = &Config{}

	// Unmarshal the YAML data into the config struct
	err = yaml.Unmarshal(data, config)
	if err != nil {
		return nil, err
	}

	baseDir, err := filepath.Abs(filepath.Dir(path))
	if err != nil {
		return nil, err
	}

	if config.Default.Egress == "" {
		config.Default.Egress = "direct"
	}
	if config.Default.DPI == "" {
		config.Default.DPI = "none"
	}
	if config.Admin.Enabled() && config.Admin.Address == "" {
		config.Admin.Address = "127.0.0.1"
	}
	if config.Detection.FallbackUpstream != "" && config.Detection.LearnedDomainsFile == "" {
		config.Detection.LearnedDomainsFile = filepath.Join(baseDir, "learned-domains.yml")
	} else if config.Detection.LearnedDomainsFile != "" && !filepath.IsAbs(config.Detection.LearnedDomainsFile) {
		config.Detection.LearnedDomainsFile = filepath.Join(baseDir, config.Detection.LearnedDomainsFile)
	}
	for path, records := range map[*string]*[]DomainRecord{
		&config.Detection.LearnAllowList: &config.Detection.LearnAllowRecords,
		&config.Detection.LearnDenyList:  &config.Detection.LearnDenyRecords,
	} {
		if *path == "" {
			continue
		}
		if !filepath.IsAbs(*path) {
			*path = filepath.Join(baseDir, *path)
		}
		list := DomainList{}
		if err := list.Load(*path); err != nil {
			return nil, fmt.Errorf("load learning filter %q: %w", *path, err)
		}
		*records = list.Records
	}

	// Load all lists. Relative paths are resolved from the configuration file.
	for i := range config.Strategy {
		config.normalizeStrategy(&config.Strategy[i])
		if config.Strategy[i].List != "" {
			if !filepath.IsAbs(config.Strategy[i].List) {
				config.Strategy[i].List = filepath.Join(baseDir, config.Strategy[i].List)
			}
			dl := DomainList{}
			err = dl.Load(config.Strategy[i].List)
			if err != nil {
				return nil, fmt.Errorf("strategy '%s' - error loading list '%s': %v", config.Strategy[i].Name, config.Strategy[i].List, err)
			}
			config.Strategy[i].ListRecords = dl.Records
		}
	}

	if err := config.Validate(); err != nil {
		return nil, err
	}

	return config, nil

}

func (c *Config) normalizeStrategy(s *Strategy) {
	if s.Egress == "" {
		switch strings.ToLower(s.Action) {
		case "socks5":
			s.Egress = "socks5"
		case "direct", "":
			s.Egress = "direct"
		default:
			s.Egress = "direct"
		}
	}
	if s.DPI == "" {
		switch strings.ToLower(s.Action) {
		case "fake-sni", "fragment", "bye":
			s.DPI = strings.ToLower(s.Action)
		default:
			s.DPI = "none"
		}
	}
	if s.Upstream == "" && s.Params != nil {
		s.Upstream = s.Params["upstream"]
	}
	if s.Fallback == "" {
		s.Fallback = c.Detection.FallbackUpstream
	}
}

func (c *Config) Validate() error {
	if c.FakeSni.MTU != 0 && (c.FakeSni.MTU < 576 || c.FakeSni.MTU > 65535) {
		return fmt.Errorf("fake-sni mtu must be between 576 and 65535")
	}
	if mode := c.Bye.SplitMode(); mode != "tcp-split" && mode != "tlsrec" {
		return fmt.Errorf("bye mode must be tcp-split or tlsrec")
	}
	if c.Bye.SplitOffset < 0 {
		return fmt.Errorf("bye split-offset must not be negative")
	}
	if c.Bye.Delay != "" {
		delay, err := time.ParseDuration(c.Bye.Delay)
		if err != nil {
			return fmt.Errorf("bye delay: %w", err)
		}
		if delay < 0 || delay > time.Second {
			return fmt.Errorf("bye delay must be between 0 and 1s")
		}
	}
	if c.Proxy.ShutdownTimeout != "" {
		timeout, err := time.ParseDuration(c.Proxy.ShutdownTimeout)
		if err != nil {
			return fmt.Errorf("proxy shutdown-timeout: %w", err)
		}
		if timeout <= 0 {
			return fmt.Errorf("proxy shutdown-timeout must be positive")
		}
	}
	for name, upstream := range c.Upstreams {
		if strings.TrimSpace(upstream.Address) == "" {
			return fmt.Errorf("upstream %q has no address", name)
		}
		if upstream.ConnectTimeout != "" {
			if _, err := time.ParseDuration(upstream.ConnectTimeout); err != nil {
				return fmt.Errorf("upstream %q connect-timeout: %w", name, err)
			}
		}
	}
	if c.Detection.FirstResponseTimeout != "" {
		if _, err := time.ParseDuration(c.Detection.FirstResponseTimeout); err != nil {
			return fmt.Errorf("detection first-response-timeout: %w", err)
		}
	}
	if c.Detection.ProbeTimeout != "" {
		if _, err := time.ParseDuration(c.Detection.ProbeTimeout); err != nil {
			return fmt.Errorf("detection probe-timeout: %w", err)
		}
	}
	if c.Detection.ProbeFailureBackoff != "" {
		backoff, err := time.ParseDuration(c.Detection.ProbeFailureBackoff)
		if err != nil {
			return fmt.Errorf("detection probe-failure-backoff: %w", err)
		}
		if backoff <= 0 {
			return fmt.Errorf("detection probe-failure-backoff must be positive")
		}
	}
	if c.Detection.LearnedMaxEntries < 0 {
		return fmt.Errorf("detection learned-max-entries must not be negative")
	}
	if c.Detection.LearnedDomainTTL != "" {
		ttl, err := time.ParseDuration(c.Detection.LearnedDomainTTL)
		if err != nil {
			return fmt.Errorf("detection learned-domain-ttl: %w", err)
		}
		if ttl < 0 {
			return fmt.Errorf("detection learned-domain-ttl must not be negative")
		}
	}
	if c.Admin.Port < 0 || c.Admin.Port > 65535 {
		return fmt.Errorf("admin port must be between 1 and 65535")
	}
	if c.UpstreamHealth.Enabled {
		for name, value := range map[string]string{
			"interval": c.UpstreamHealth.Interval,
			"timeout":  c.UpstreamHealth.Timeout,
			"cooldown": c.UpstreamHealth.Cooldown,
		} {
			if value == "" {
				continue
			}
			duration, err := time.ParseDuration(value)
			if err != nil {
				return fmt.Errorf("upstream-health %s: %w", name, err)
			}
			if duration <= 0 {
				return fmt.Errorf("upstream-health %s must be positive", name)
			}
		}
		if c.UpstreamHealth.FailureThreshold < 0 {
			return fmt.Errorf("upstream-health failure-threshold must not be negative")
		}
	}
	for _, s := range c.Strategy {
		if err := c.validatePolicy(s.Name, s.Egress, s.DPI, s.Upstream, s.Fallback); err != nil {
			return err
		}
	}
	return c.validatePolicy("default", c.Default.Egress, c.Default.DPI, c.Default.Upstream, c.Default.Fallback)
}

func (c *Config) validatePolicy(name, egress, dpi, upstream, fallback string) error {
	if egress != "direct" && egress != "socks5" {
		return fmt.Errorf("policy %q has unsupported egress %q", name, egress)
	}
	if dpi != "none" && dpi != "fragment" && dpi != "fake-sni" && dpi != "bye" {
		return fmt.Errorf("policy %q has unsupported dpi mode %q", name, dpi)
	}
	if egress == "socks5" {
		if _, ok := c.Upstreams[upstream]; !ok {
			return fmt.Errorf("policy %q references unknown upstream %q", name, upstream)
		}
	}
	if fallback != "" && fallback != "none" {
		if _, ok := c.Upstreams[fallback]; !ok {
			return fmt.Errorf("policy %q references unknown fallback %q", name, fallback)
		}
	}
	return nil
}

func (c *Config) PolicyFor(host, learnedRoute, learnedUpstream string) ResolvedPolicy {
	policy := ResolvedPolicy{
		Name:     "default",
		Egress:   c.Default.Egress,
		DPI:      c.Default.DPI,
		Upstream: c.Default.Upstream,
		Fallback: c.Default.Fallback,
	}
	if policy.Fallback == "" {
		policy.Fallback = c.Detection.FallbackUpstream
	}

	for _, strategy := range c.Strategy {
		if matched, params := strategy.match(host); matched {
			policy = ResolvedPolicy{
				Name:     strategy.Name,
				Egress:   strategy.Egress,
				DPI:      strategy.DPI,
				Upstream: strategy.Upstream,
				Fallback: strategy.Fallback,
				Params:   params,
			}
			break
		}
	}

	// A statically selected SOCKS5 upstream always wins. Learned routing only
	// replaces direct policies which permit fallback.
	_, learnedUpstreamExists := c.Upstreams[learnedUpstream]
	if learnedRoute == "direct+bye" && policy.Egress != "socks5" && policy.Fallback != "none" {
		policy.Name = "learned-domain-bye"
		policy.Egress = "direct"
		policy.DPI = "bye"
		policy.Upstream = ""
	} else if learnedRoute == "socks5" && learnedUpstreamExists && policy.Egress != "socks5" && policy.Fallback != "none" {
		policy.Name = "learned-domain"
		policy.Egress = "socks5"
		policy.DPI = "none"
		policy.Upstream = learnedUpstream
	}
	return policy
}

func (s Strategy) match(host string) (bool, map[string]string) {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	for _, record := range s.ListRecords {
		if record.Regexp != nil && record.Regexp.MatchString(host) {
			params := make(map[string]string, len(s.Params)+1)
			for key, value := range s.Params {
				params[key] = value
			}
			if record.Actions != nil {
				for key, value := range *record.Actions {
					params[key] = value
				}
			}
			return true, params
		}
	}
	return false, nil
}

func recordsMatch(records []DomainRecord, host string) bool {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	for _, record := range records {
		if record.Regexp != nil && record.Regexp.MatchString(host) {
			return true
		}
	}
	return false
}

func (p ResolvedPolicy) TTL(defaultTTL int) int {
	if p.Params == nil || p.Params["ttl"] == "" {
		return defaultTTL
	}
	ttl, err := strconv.Atoi(p.Params["ttl"])
	if err != nil || ttl < 1 || ttl > 255 {
		return defaultTTL
	}
	return ttl
}

func (p ResolvedPolicy) FakeSNI(defaultDecoy, original string) string {
	if p.Params != nil && strings.TrimSpace(p.Params["fake-sni"]) != "" {
		return strings.TrimSpace(p.Params["fake-sni"])
	}
	if strings.TrimSpace(defaultDecoy) != "" {
		return strings.TrimSpace(defaultDecoy)
	}
	if len(original) == 0 {
		return ""
	}
	return original[:len(original)-1] + "x"
}

func parseDuration(value string, fallback time.Duration) time.Duration {
	if value == "" {
		return fallback
	}
	d, err := time.ParseDuration(value)
	if err != nil {
		return fallback
	}
	return d
}

func (c *Config) IsFakeStrategy(targetHost string) (ok bool, replace string) {
	replace = targetHost

	for _, cr := range c.Strategy {
		if cr.Action != "fake-sni" {
			continue
		}
		for _, rec := range cr.ListRecords {
			if rec.Regexp != nil {
				if rec.Regexp.MatchString(targetHost) {
					ok = true
					replace = replace[:len(replace)-1] + "x"
					return
				}
			}
		}
	}

	return false, replace
}
