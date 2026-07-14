package routing

import (
	"path/filepath"
	"testing"
	"time"
)

func TestStorePersistsExactHosts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "learned.yml")
	store, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	added, err := store.Add("WWW.Example.COM.", "vpn", "test")
	if err != nil || !added {
		t.Fatalf("Add() = %v, %v; want true, nil", added, err)
	}
	if _, ok := store.Lookup("www.example.com"); !ok {
		t.Fatal("exact learned host was not found")
	}
	if _, ok := store.Lookup("api.example.com"); ok {
		t.Fatal("learned host unexpectedly matched a sibling")
	}
	if added, err := store.Add("www.example.com", "vpn-2", "updated"); err != nil || !added {
		t.Fatalf("updated Add() = %v, %v", added, err)
	}

	reloaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	entry, ok := reloaded.Lookup("www.example.com")
	if !ok || entry.Upstream != "vpn-2" {
		t.Fatalf("reloaded entry = %#v, %v", entry, ok)
	}
}

func TestStoreUsageExpirationAndDelete(t *testing.T) {
	path := filepath.Join(t.TempDir(), "learned.yml")
	store, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Add("used.example", "vpn", "test"); err != nil {
		t.Fatal(err)
	}
	entry, _ := store.Lookup("used.example")
	usedAt := entry.LearnedAt.Add(10 * time.Minute)
	if !store.MarkUsed("used.example", usedAt) || !store.MarkUsed("used.example", usedAt) {
		t.Fatal("MarkUsed() did not find route")
	}
	if err := store.Flush(); err != nil {
		t.Fatal(err)
	}
	reloaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	entry, ok := reloaded.Lookup("used.example")
	if !ok || entry.HitCount != 2 || !entry.LastUsedAt.Equal(usedAt) {
		t.Fatalf("usage entry = %#v, %v", entry, ok)
	}
	if _, ok := reloaded.LookupActive("used.example", time.Hour, entry.LearnedAt.Add(2*time.Hour)); ok {
		t.Fatal("expired route returned by LookupActive")
	}
	removed, err := reloaded.PruneExpired(time.Hour, entry.LearnedAt.Add(2*time.Hour))
	if err != nil || removed != 1 {
		t.Fatalf("PruneExpired() = %d, %v", removed, err)
	}
	if deleted, err := reloaded.Delete("used.example"); err != nil || deleted {
		t.Fatalf("Delete() after prune = %v, %v", deleted, err)
	}
}

func TestStoreDeletePersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "learned.yml")
	store, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Add("delete.example", "vpn", "test"); err != nil {
		t.Fatal(err)
	}
	if deleted, err := store.Delete("delete.example"); err != nil || !deleted {
		t.Fatalf("Delete() = %v, %v", deleted, err)
	}
	reloaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := reloaded.Lookup("delete.example"); ok {
		t.Fatal("deleted route was persisted")
	}
}

func TestStoreDeduplicates(t *testing.T) {
	store, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if added, err := store.Add("example.com", "vpn", "first"); err != nil || !added {
		t.Fatalf("first Add() = %v, %v", added, err)
	}
	if added, err := store.Add("example.com", "vpn", "second"); err != nil || added {
		t.Fatalf("second Add() = %v, %v; want false, nil", added, err)
	}
}
