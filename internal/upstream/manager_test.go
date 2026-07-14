package upstream

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/vponomarev/socks-proxy/internal/config"
)

func TestCircuitBreakerTransitions(t *testing.T) {
	manager := New(map[string]config.Upstream{"vpn": {Address: "vpn:1080"}}, config.UpstreamHealth{
		Enabled: true, FailureThreshold: 2, Cooldown: "1m",
	})
	now := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	manager.now = func() time.Time { return now }

	if !manager.Allow("vpn") {
		t.Fatal("closed circuit rejected request")
	}
	if state := manager.Record("vpn", errors.New("first")); state.Circuit != "closed" {
		t.Fatalf("first failure state = %#v", state)
	}
	if state := manager.Record("vpn", errors.New("second")); state.Circuit != "open" {
		t.Fatalf("second failure state = %#v", state)
	}
	if manager.Allow("vpn") {
		t.Fatal("open circuit admitted request before cooldown")
	}

	now = now.Add(61 * time.Second)
	if !manager.Allow("vpn") {
		t.Fatal("circuit did not admit half-open probe")
	}
	if manager.Allow("vpn") {
		t.Fatal("half-open circuit admitted a second probe")
	}
	if state := manager.Record("vpn", nil); state.Circuit != "closed" || state.Health != "healthy" || state.ConsecutiveFailures != 0 {
		t.Fatalf("recovered state = %#v", state)
	}
}

func TestActiveCheckOpensAndRecoversCircuit(t *testing.T) {
	manager := New(map[string]config.Upstream{"vpn": {Address: "vpn:1080"}}, config.UpstreamHealth{
		Enabled: true, FailureThreshold: 1, Timeout: "1s",
	})
	manager.check = func(context.Context, config.Upstream) error { return errors.New("offline") }
	states := manager.CheckAll(context.Background())
	if len(states) != 1 || states[0].Circuit != "open" || states[0].Health != "unhealthy" {
		t.Fatalf("failed check states = %#v", states)
	}
	manager.check = func(context.Context, config.Upstream) error { return nil }
	states = manager.CheckAll(context.Background())
	if states[0].Circuit != "closed" || states[0].Health != "healthy" {
		t.Fatalf("recovered check states = %#v", states)
	}
}
