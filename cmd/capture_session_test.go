package main

import (
	"net"
	"testing"
	"time"
)

func TestRingSessionBufferReturnsNewestLiveSession(t *testing.T) {
	now := time.Now()
	key := SessionInfo{
		SrcIP: net.IPv4(192, 0, 2, 1), DstIP: net.IPv4(198, 51, 100, 1),
		SrcPort: 40000, DstPort: 443,
	}
	ring := RingSessionBuffer{}
	old := key
	old.ISN = 100
	old.SeenAt = now.Add(-2 * time.Minute)
	ring.Append(old)
	recent := key
	recent.ISN = 200
	recent.SeenAt = now
	ring.Append(recent)

	ok, got := ring.Lookup(key)
	if !ok || got.ISN != recent.ISN {
		t.Fatalf("Lookup() = %t, ISN %d", ok, got.ISN)
	}
}

func TestRingSessionBufferUpdatesTCPState(t *testing.T) {
	key := SessionInfo{
		SrcIP: net.IPv4(192, 0, 2, 1), DstIP: net.IPv4(198, 51, 100, 1),
		SrcPort: 40000, DstPort: 443, ISN: 100,
	}
	ring := RingSessionBuffer{}
	ring.Append(key)
	update := key
	update.ISN = 0
	update.SeenAt = time.Now()
	update.HasTimestamp = true
	update.ClientTS = 3000
	update.ServerTS = 4000
	update.Window = 502
	if !ring.Update(update) {
		t.Fatal("Update did not find session")
	}
	ok, got := ring.Lookup(key)
	if !ok || got.ISN != 100 || got.ClientTS != 3000 || got.ServerTS != 4000 || got.Window != 502 {
		t.Fatalf("Lookup() = %t, %#v", ok, got)
	}
}
