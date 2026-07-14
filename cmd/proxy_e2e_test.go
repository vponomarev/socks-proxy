package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"testing"
	"time"

	"github.com/vponomarev/socks-proxy/internal/config"
	"github.com/vponomarev/socks-proxy/internal/monitor"
	"github.com/vponomarev/socks-proxy/internal/routing"
	"github.com/vponomarev/socks-proxy/internal/upstream"
)

func TestProxyDirectEndToEnd(t *testing.T) {
	targetAddress, stopTarget := startEchoTarget(t)
	defer stopTarget()
	host, portText, err := net.SplitHostPort(targetAddress)
	if err != nil {
		t.Fatal(err)
	}
	port, err := net.LookupPort("tcp", portText)
	if err != nil {
		t.Fatal(err)
	}

	setProxyTestGlobals(t, &config.Config{
		Default: config.DefaultPolicy{Egress: "direct", DPI: "none", Fallback: "none"},
	})
	client, wait := startProxySession(t)
	defer wait()

	proxyGreeting(t, client)
	proxyConnect(t, client, host, uint16(port))
	assertEcho(t, client, []byte("direct payload"))
	client.Close()
}

func TestExampleConfigurationsLoad(t *testing.T) {
	for _, path := range []string{"proxy.example.yml", "vpn-proxy.example.yml"} {
		if _, err := config.LoadConfig(path); err != nil {
			t.Errorf("LoadConfig(%q): %v", path, err)
		}
	}
}

func TestProxyStaticNamedUpstreamEndToEnd(t *testing.T) {
	upstreamAddress, targets, stopUpstream := startEchoSOCKS5(t)
	defer stopUpstream()
	cfg := &config.Config{
		Upstreams: map[string]config.Upstream{
			"segment": {Address: upstreamAddress, ConnectTimeout: "1s"},
		},
		Default: config.DefaultPolicy{Egress: "direct", DPI: "none", Fallback: "none"},
		Strategy: []config.Strategy{
			{
				Name:     "fixed-segment",
				Egress:   "socks5",
				DPI:      "none",
				Upstream: "segment",
				Fallback: "none",
				ListRecords: []config.DomainRecord{
					{Regexp: regexp.MustCompile(`^fixed\.example$`)},
				},
			},
		},
	}
	setProxyTestGlobals(t, cfg)
	client, wait := startProxySession(t)
	defer wait()

	proxyGreeting(t, client)
	proxyConnect(t, client, "fixed.example", 443)
	assertEcho(t, client, []byte("static upstream payload"))
	client.Close()
	target := <-targets
	if target.host != "fixed.example" || target.port != 443 {
		t.Fatalf("upstream target = %#v", target)
	}
}

func TestProxyLearnedDomainUsesFallbackUpstream(t *testing.T) {
	upstreamAddress, targets, stopUpstream := startEchoSOCKS5(t)
	defer stopUpstream()
	cfg := &config.Config{
		Upstreams: map[string]config.Upstream{
			"vpn": {Address: upstreamAddress, ConnectTimeout: "1s"},
		},
		Detection: config.Detection{FallbackUpstream: "vpn"},
		Default:   config.DefaultPolicy{Egress: "direct", DPI: "none"},
	}
	store, err := routing.Load("")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Add("learned.example", "vpn", "test"); err != nil {
		t.Fatal(err)
	}
	setProxyTestGlobalsWithStore(t, cfg, store)
	client, wait := startProxySession(t)
	defer wait()

	proxyGreeting(t, client)
	proxyConnect(t, client, "learned.example", 443)
	assertEcho(t, client, []byte("learned upstream payload"))
	client.Close()
	target := <-targets
	if target.host != "learned.example" || target.port != 443 {
		t.Fatalf("upstream target = %#v", target)
	}
}

func TestProxyDirectConnectFailureFallsBackAndLearns(t *testing.T) {
	upstreamAddress, targets, stopUpstream := startEchoSOCKS5(t)
	defer stopUpstream()
	cfg := &config.Config{
		Upstreams: map[string]config.Upstream{
			"vpn": {Address: upstreamAddress, ConnectTimeout: "1s"},
		},
		Detection: config.Detection{FallbackUpstream: "vpn"},
		Default:   config.DefaultPolicy{Egress: "direct", DPI: "none", Fallback: "vpn"},
	}
	store, err := routing.Load("")
	if err != nil {
		t.Fatal(err)
	}
	setProxyTestGlobalsWithStore(t, cfg, store)
	forceDirectDialFailure(t)
	ProxyMetrics = monitor.New()
	client, wait := startProxySession(t)
	defer wait()

	proxyGreeting(t, client)
	proxyConnect(t, client, "connect-fallback.example", 443)
	assertEcho(t, client, []byte("connect fallback payload"))
	client.Close()
	target := <-targets
	if target.host != "connect-fallback.example" || target.port != 443 {
		t.Fatalf("upstream target = %#v", target)
	}
	entry, ok := store.Lookup("connect-fallback.example")
	if !ok || entry.Upstream != "vpn" || entry.Reason != "direct-connect-failure-upstream-success" {
		t.Fatalf("learned route = %#v, %v", entry, ok)
	}
	if ProxyMetrics.Snapshot().FallbackResults["connect_failure_success/vpn"] != 1 {
		t.Fatalf("fallback metrics = %#v", ProxyMetrics.Snapshot().FallbackResults)
	}
}

func TestProxyDirectAndFallbackConnectFailureReturnsError(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	unavailableAddress := listener.Addr().String()
	listener.Close()
	cfg := &config.Config{
		Upstreams: map[string]config.Upstream{
			"vpn": {Address: unavailableAddress, ConnectTimeout: "100ms"},
		},
		Detection: config.Detection{FallbackUpstream: "vpn"},
		Default:   config.DefaultPolicy{Egress: "direct", DPI: "none", Fallback: "vpn"},
	}
	store, err := routing.Load("")
	if err != nil {
		t.Fatal(err)
	}
	setProxyTestGlobalsWithStore(t, cfg, store)
	forceDirectDialFailure(t)
	client, wait := startProxySession(t)
	defer wait()

	proxyGreeting(t, client)
	if reply := proxyConnectReply(t, client, "unreachable.example", 443); reply == 0 {
		t.Fatal("SOCKS CONNECT unexpectedly succeeded")
	}
	if _, ok := store.Lookup("unreachable.example"); ok {
		t.Fatal("failed fallback was learned")
	}
}

func TestDialUpstreamRejectsOpenCircuit(t *testing.T) {
	cfg := &config.Config{
		Upstreams: map[string]config.Upstream{"vpn": {Address: "127.0.0.1:1", ConnectTimeout: "100ms"}},
	}
	setProxyTestGlobals(t, cfg)
	UpstreamManager = upstream.New(cfg.Upstreams, config.UpstreamHealth{
		Enabled: true, FailureThreshold: 1, Cooldown: "1h",
	})
	UpstreamManager.Record("vpn", errors.New("offline"))
	if _, err := dialUpstream("vpn", "example.com", 443); !errors.Is(err, upstream.ErrCircuitOpen) {
		t.Fatalf("dialUpstream() error = %v; want ErrCircuitOpen", err)
	}
}

func forceDirectDialFailure(t *testing.T) {
	t.Helper()
	previous := directDial
	directDial = func(_, _ string, _ time.Duration) (net.Conn, error) {
		return nil, errors.New("forced direct dial failure")
	}
	t.Cleanup(func() { directDial = previous })
}

func setProxyTestGlobals(t *testing.T, cfg *config.Config) {
	t.Helper()
	store, err := routing.Load("")
	if err != nil {
		t.Fatal(err)
	}
	setProxyTestGlobalsWithStore(t, cfg, store)
}

func setProxyTestGlobalsWithStore(t *testing.T, cfg *config.Config, store *routing.Store) {
	t.Helper()
	oldConfig, oldRoutes, oldMetrics, oldUpstreams := Cfg, LearnedRoutes, ProxyMetrics, UpstreamManager
	Cfg, LearnedRoutes, ProxyMetrics, UpstreamManager = cfg, store, nil, nil
	t.Cleanup(func() {
		Cfg, LearnedRoutes, ProxyMetrics, UpstreamManager = oldConfig, oldRoutes, oldMetrics, oldUpstreams
	})
}

func startProxySession(t *testing.T) (net.Conn, func()) {
	t.Helper()
	client, server := net.Pipe()
	if err := client.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		(&Socks5{clientConn: server, UniqNo: 100, firstResponse: make(chan struct{})}).AcceptConnection()
	}()
	return client, func() {
		client.Close()
		<-done
	}
}

func proxyGreeting(t *testing.T, conn net.Conn) {
	t.Helper()
	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 2)
	if _, err := io.ReadFull(conn, response); err != nil {
		t.Fatal(err)
	}
	if response[0] != 5 || response[1] != 0 {
		t.Fatalf("SOCKS greeting response = %v", response)
	}
}

func proxyConnect(t *testing.T, conn net.Conn, host string, port uint16) {
	t.Helper()
	if reply := proxyConnectReply(t, conn, host, port); reply != 0 {
		t.Fatalf("SOCKS CONNECT reply = %d", reply)
	}
}

func proxyConnectReply(t *testing.T, conn net.Conn, host string, port uint16) byte {
	t.Helper()
	request := []byte{5, 1, 0}
	ip := net.ParseIP(host)
	if ip4 := ip.To4(); ip4 != nil {
		request = append(request, 1)
		request = append(request, ip4...)
	} else {
		request = append(request, 3, byte(len(host)))
		request = append(request, host...)
	}
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, port)
	request = append(request, portBytes...)
	if _, err := conn.Write(request); err != nil {
		t.Fatal(err)
	}
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		t.Fatal(err)
	}
	if header[0] != 5 {
		t.Fatalf("SOCKS CONNECT response = %v", header)
	}
	if err := discardTestAddress(conn, header[3]); err != nil {
		t.Fatal(err)
	}
	return header[1]
}

func assertEcho(t *testing.T, conn net.Conn, payload []byte) {
	t.Helper()
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, response); err != nil {
		t.Fatal(err)
	}
	if string(response) != string(payload) {
		t.Fatalf("echo response = %q; want %q", response, payload)
	}
}

func startEchoTarget(t *testing.T) (string, func()) {
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
		_, _ = io.Copy(conn, conn)
	}()
	return listener.Addr().String(), func() {
		listener.Close()
		<-done
	}
}

type testTarget struct {
	host string
	port uint16
}

func startEchoSOCKS5(t *testing.T) (string, <-chan testTarget, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	targets := make(chan testTarget, 1)
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
		if _, err := io.CopyN(io.Discard, conn, int64(header[1])); err != nil {
			return
		}
		if _, err := conn.Write([]byte{5, 0}); err != nil {
			return
		}
		request := make([]byte, 4)
		if _, err := io.ReadFull(conn, request); err != nil {
			return
		}
		target, err := readTestTarget(conn, request[3])
		if err != nil {
			return
		}
		targets <- target
		if _, err := conn.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0}); err != nil {
			return
		}
		_, _ = io.Copy(conn, conn)
	}()
	return listener.Addr().String(), targets, func() {
		listener.Close()
		<-done
	}
}

func readTestTarget(conn net.Conn, atyp byte) (testTarget, error) {
	var host string
	switch atyp {
	case 1:
		address := make([]byte, 4)
		if _, err := io.ReadFull(conn, address); err != nil {
			return testTarget{}, err
		}
		host = net.IP(address).String()
	case 3:
		length := make([]byte, 1)
		if _, err := io.ReadFull(conn, length); err != nil {
			return testTarget{}, err
		}
		address := make([]byte, int(length[0]))
		if _, err := io.ReadFull(conn, address); err != nil {
			return testTarget{}, err
		}
		host = string(address)
	default:
		return testTarget{}, fmt.Errorf("unsupported test address type %d", atyp)
	}
	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBytes); err != nil {
		return testTarget{}, err
	}
	return testTarget{host: host, port: binary.BigEndian.Uint16(portBytes)}, nil
}
