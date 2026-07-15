package main

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/vponomarev/socks-proxy/internal/config"
	"github.com/vponomarev/socks-proxy/internal/libtls"
	"github.com/vponomarev/socks-proxy/internal/routing"
)

func TestProbeCoordinatorBackoff(t *testing.T) {
	coordinator := newProbeCoordinator()
	now := time.Now()
	if started, reason := coordinator.Start("example.com", now); !started || reason != "" {
		t.Fatalf("first start = %v, %q", started, reason)
	}
	if started, reason := coordinator.Start("EXAMPLE.COM.", now); started || reason != "already_in_progress" {
		t.Fatalf("concurrent start = %v, %q", started, reason)
	}
	coordinator.Done("example.com", now.Add(time.Minute))
	if started, reason := coordinator.Start("example.com", now.Add(30*time.Second)); started || reason != "failure_backoff" {
		t.Fatalf("backoff start = %v, %q", started, reason)
	}
	if started, reason := coordinator.Start("example.com", now.Add(2*time.Minute)); !started || reason != "" {
		t.Fatalf("post-backoff start = %v, %q", started, reason)
	}
	coordinator.Done("example.com", time.Time{})
}

func TestBlockCandidateLearnsSuccessfulFallback(t *testing.T) {
	address, stop := startTestSOCKS5(t, []byte("client hello"))
	defer stop()

	oldConfig, oldRoutes, oldDirectDialContext := Cfg, LearnedRoutes, directDialContext
	t.Cleanup(func() {
		Cfg, LearnedRoutes = oldConfig, oldRoutes
		directDialContext = oldDirectDialContext
	})
	directDialContext = func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("direct probe unavailable")
	}
	Cfg = &config.Config{
		Upstreams: map[string]config.Upstream{
			"vpn": {Address: address, ConnectTimeout: "1s"},
		},
		Detection: config.Detection{
			FirstResponseTimeout: "1ms",
			ProbeTimeout:         "1s",
		},
	}
	var err error
	LearnedRoutes, err = routing.Load("")
	if err != nil {
		t.Fatal(err)
	}

	clientConn, clientPeer := net.Pipe()
	targetConn, targetPeer := net.Pipe()
	defer clientPeer.Close()
	defer targetPeer.Close()
	session := &Socks5{
		UniqNo:        1,
		TargetHost:    "example.com",
		TargetPort:    443,
		ConnTargetIP:  "203.0.113.10",
		clientConn:    clientConn,
		targetConn:    targetConn,
		Policy:        config.ResolvedPolicy{Egress: "direct", Fallback: "vpn"},
		firstResponse: make(chan struct{}),
	}
	session.monitorBlockCandidate("example.com", []byte("client hello"))

	entry, ok := LearnedRoutes.Lookup("example.com")
	if !ok || entry.Route != routing.RouteSOCKS5 || entry.Upstream != "vpn" {
		t.Fatalf("learned route = %#v, %v", entry, ok)
	}
}

func TestBlockCandidateLearnsSuccessfulBye(t *testing.T) {
	hello, err := libtls.GenerateClientHello("example.com", 1400)
	if err != nil {
		t.Fatal(err)
	}
	oldConfig, oldRoutes, oldDirectDialContext := Cfg, LearnedRoutes, directDialContext
	t.Cleanup(func() {
		Cfg, LearnedRoutes = oldConfig, oldRoutes
		directDialContext = oldDirectDialContext
	})
	Cfg = &config.Config{
		Bye:       config.Bye{Mode: "tcp-split", Delay: "0s"},
		Detection: config.Detection{FirstResponseTimeout: "1ms", ProbeTimeout: "1s"},
	}
	LearnedRoutes, err = routing.Load("")
	if err != nil {
		t.Fatal(err)
	}
	directDialContext = func(context.Context, string, string) (net.Conn, error) {
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			payload := make([]byte, len(hello))
			if _, readErr := io.ReadFull(server, payload); readErr == nil {
				server.Write([]byte{0x16})
			}
		}()
		return client, nil
	}

	clientConn, clientPeer := net.Pipe()
	targetConn, targetPeer := net.Pipe()
	defer clientPeer.Close()
	defer targetPeer.Close()
	session := &Socks5{
		UniqNo:        2,
		TargetHost:    "example.com",
		TargetPort:    443,
		ConnTargetIP:  "203.0.113.10",
		clientConn:    clientConn,
		targetConn:    targetConn,
		Policy:        config.ResolvedPolicy{Egress: "direct", Fallback: "vpn"},
		firstResponse: make(chan struct{}),
	}
	session.monitorBlockCandidate("example.com", hello)

	entry, ok := LearnedRoutes.Lookup("example.com")
	if !ok || entry.Route != routing.RouteBye || entry.Upstream != "" {
		t.Fatalf("learned route = %#v, %v", entry, ok)
	}
}

func startTestSOCKS5(t *testing.T, expectedPayload []byte) (string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		header := make([]byte, 2)
		if _, err := io.ReadFull(conn, header); err != nil {
			return
		}
		methods := make([]byte, int(header[1]))
		if _, err := io.ReadFull(conn, methods); err != nil {
			return
		}
		if _, err := conn.Write([]byte{5, 0}); err != nil {
			return
		}
		request := make([]byte, 4)
		if _, err := io.ReadFull(conn, request); err != nil {
			return
		}
		if err := discardTestAddress(conn, request[3]); err != nil {
			return
		}
		if _, err := conn.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0}); err != nil {
			return
		}
		payload := make([]byte, len(expectedPayload))
		if _, err := io.ReadFull(conn, payload); err != nil {
			return
		}
		conn.Write([]byte{0x16})
	}()
	return listener.Addr().String(), func() {
		listener.Close()
		<-done
	}
}

func discardTestAddress(conn net.Conn, atyp byte) error {
	length := 0
	switch atyp {
	case 1:
		length = 4
	case 4:
		length = 16
	case 3:
		buf := make([]byte, 1)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return err
		}
		length = int(buf[0])
	}
	_, err := io.CopyN(io.Discard, conn, int64(length+2))
	return err
}
