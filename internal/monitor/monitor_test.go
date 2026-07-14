package monitor

import (
	"testing"
	"time"
)

func TestSnapshotTracksSessionsRoutesAndFallback(t *testing.T) {
	m := New()
	m.SessionStarted()
	m.RouteDecision("learned-domain", "socks5", "vpn")
	m.FallbackResult("success", "vpn")
	m.SessionFinished(100, 200, time.Second, "socks5", "completed")
	m.SetLearnedRoutes(3)

	snapshot := m.Snapshot()
	if snapshot.SessionsStarted != 1 || snapshot.SessionsActive != 0 || snapshot.SessionsComplete != 1 {
		t.Fatalf("session snapshot = %#v", snapshot)
	}
	if snapshot.BytesSent != 100 || snapshot.BytesReceived != 200 || snapshot.LearnedRoutes != 3 {
		t.Fatalf("traffic snapshot = %#v", snapshot)
	}
	if snapshot.RouteDecisions["learned-domain/socks5/vpn"] != 1 || snapshot.FallbackResults["success/vpn"] != 1 {
		t.Fatalf("decision snapshot = %#v", snapshot)
	}
}
