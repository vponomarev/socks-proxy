package routing

import (
	"path/filepath"
	"testing"
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
