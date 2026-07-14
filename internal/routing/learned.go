package routing

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v2"
)

type LearnedDomain struct {
	Host       string    `yaml:"host" json:"host"`
	Upstream   string    `yaml:"upstream" json:"upstream"`
	LearnedAt  time.Time `yaml:"learned-at" json:"learned_at"`
	LastUsedAt time.Time `yaml:"last-used-at,omitempty" json:"last_used_at,omitempty"`
	HitCount   uint64    `yaml:"hit-count,omitempty" json:"hit_count"`
	Reason     string    `yaml:"reason" json:"reason"`
}

type learnedFile struct {
	Version int             `yaml:"version"`
	Domains []LearnedDomain `yaml:"domains"`
}

// Store is an exact-host learned routing table. Exact matching is deliberate:
// automatically expanding a host to its parent domain can route unrelated
// services through an upstream.
type Store struct {
	mu      sync.RWMutex
	path    string
	domains map[string]LearnedDomain
	dirty   bool
}

func Load(path string) (*Store, error) {
	store := &Store{
		path:    path,
		domains: make(map[string]LearnedDomain),
	}
	if path == "" {
		return store, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return store, nil
		}
		return nil, fmt.Errorf("read learned domains: %w", err)
	}
	var file learnedFile
	if err := yaml.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("parse learned domains: %w", err)
	}
	for _, entry := range file.Domains {
		entry.Host = normalizeHost(entry.Host)
		if entry.Host == "" || entry.Upstream == "" {
			continue
		}
		store.domains[entry.Host] = entry
	}
	return store, nil
}

func (s *Store) Lookup(host string) (LearnedDomain, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	entry, ok := s.domains[normalizeHost(host)]
	return entry, ok
}

// LookupActive returns a learned route unless it is older than ttl. A zero TTL
// disables expiration. Expired entries are removed by PruneExpired.
func (s *Store) LookupActive(host string, ttl time.Duration, now time.Time) (LearnedDomain, bool) {
	entry, ok := s.Lookup(host)
	if !ok || (ttl > 0 && now.Sub(entry.LearnedAt) >= ttl) {
		return LearnedDomain{}, false
	}
	return entry, true
}

// MarkUsed updates in-memory usage data. Flush persists batched updates so a
// busy proxy does not rewrite the YAML file for every connection.
func (s *Store) MarkUsed(host string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	host = normalizeHost(host)
	entry, ok := s.domains[host]
	if !ok {
		return false
	}
	entry.HitCount++
	entry.LastUsedAt = now
	s.domains[host] = entry
	s.dirty = true
	return true
}

func (s *Store) Add(host, upstream, reason string) (bool, error) {
	host = normalizeHost(host)
	if host == "" {
		return false, fmt.Errorf("learned domain host is empty")
	}
	if upstream == "" {
		return false, fmt.Errorf("learned domain upstream is empty")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	current, existed := s.domains[host]
	if existed && current.Upstream == upstream {
		return false, nil
	}
	s.domains[host] = LearnedDomain{
		Host:      host,
		Upstream:  upstream,
		LearnedAt: time.Now(),
		Reason:    reason,
	}
	if err := s.saveLocked(); err != nil {
		if existed {
			s.domains[host] = current
		} else {
			delete(s.domains, host)
		}
		return false, err
	}
	s.dirty = false
	return true, nil
}

func (s *Store) Delete(host string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	host = normalizeHost(host)
	entry, existed := s.domains[host]
	if !existed {
		return false, nil
	}
	delete(s.domains, host)
	if err := s.saveLocked(); err != nil {
		s.domains[host] = entry
		return false, err
	}
	s.dirty = false
	return true, nil
}

func (s *Store) PruneExpired(ttl time.Duration, now time.Time) (int, error) {
	if ttl <= 0 {
		return 0, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := make(map[string]LearnedDomain)
	for host, entry := range s.domains {
		if now.Sub(entry.LearnedAt) >= ttl {
			removed[host] = entry
			delete(s.domains, host)
		}
	}
	if len(removed) == 0 {
		return 0, nil
	}
	if err := s.saveLocked(); err != nil {
		for host, entry := range removed {
			s.domains[host] = entry
		}
		return 0, err
	}
	s.dirty = false
	return len(removed), nil
}

func (s *Store) Flush() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.dirty {
		return nil
	}
	if err := s.saveLocked(); err != nil {
		return err
	}
	s.dirty = false
	return nil
}

func (s *Store) Entries() []LearnedDomain {
	s.mu.RLock()
	defer s.mu.RUnlock()
	entries := make([]LearnedDomain, 0, len(s.domains))
	for _, entry := range s.domains {
		entries = append(entries, entry)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Host < entries[j].Host })
	return entries
}

func (s *Store) saveLocked() error {
	if s.path == "" {
		return nil
	}
	entries := make([]LearnedDomain, 0, len(s.domains))
	for _, entry := range s.domains {
		entries = append(entries, entry)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Host < entries[j].Host })
	data, err := yaml.Marshal(learnedFile{Version: 1, Domains: entries})
	if err != nil {
		return fmt.Errorf("encode learned domains: %w", err)
	}

	dir := filepath.Dir(s.path)
	tmp, err := os.CreateTemp(dir, ".learned-domains-*.tmp")
	if err != nil {
		return fmt.Errorf("create learned domains temporary file: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write learned domains: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync learned domains: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close learned domains: %w", err)
	}
	if err := os.Rename(tmpPath, s.path); err != nil {
		return fmt.Errorf("replace learned domains: %w", err)
	}
	return nil
}

func normalizeHost(host string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
}
