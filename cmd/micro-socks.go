package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/vponomarev/socks-proxy/internal/admin"
	"github.com/vponomarev/socks-proxy/internal/config"
	"github.com/vponomarev/socks-proxy/internal/monitor"
	"github.com/vponomarev/socks-proxy/internal/routing"
	"github.com/vponomarev/socks-proxy/internal/upstream"
)

const (
	socksVersion    byte = 5
	fragmentSize         = 200 // Размер фрагмента в байтах
	initialFragSize      = 200 // Первые N байт для фрагментации
)

type Fragmenter struct {
	enabled    bool
	sentBytes  int
	totalLimit int
}

var (
	RSB             RingSessionBuffer
	SerSentBuffer   chan gopacket.SerializeBuffer
	paramTTL        = flag.Int("ttl", 7, "TTL for fake packets")
	configPath      = flag.String("config", "proxy.yml", "Path to config file, default `proxy.yml`")
	Cfg             *config.Config
	LearnedRoutes   *routing.Store
	ProxyMetrics    *monitor.Monitor
	UpstreamManager *upstream.Manager
)

func CaptureSessionInfo(conn net.Conn) (ok bool, si SessionInfo) {
	// Capture association
	si = SessionInfo{
		SrcIP:   conn.LocalAddr().(*net.TCPAddr).IP,
		DstIP:   conn.RemoteAddr().(*net.TCPAddr).IP,
		SrcPort: uint16(conn.LocalAddr().(*net.TCPAddr).Port),
		DstPort: uint16(conn.RemoteAddr().(*net.TCPAddr).Port),
		ISN:     0,
	}

	return RSB.Lookup(si)
}

func main() {
	flag.Parse()

	var err error
	Cfg, err = config.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("Error loading config file [%s]: %v\n", *configPath, err)
	}
	LearnedRoutes, err = routing.Load(Cfg.Detection.LearnedDomainsFile)
	if err != nil {
		log.Fatalf("Error loading learned domains: %v\n", err)
	}
	ttl := Cfg.Detection.LearnedTTL()
	if removed, pruneErr := LearnedRoutes.PruneExpired(ttl, time.Now()); pruneErr != nil {
		log.Fatalf("Error pruning learned domains: %v", pruneErr)
	} else if removed > 0 {
		log.Printf("Pruned %d expired learned domain routes", removed)
	}
	ProxyMetrics = monitor.New()
	ProxyMetrics.SetLearnedRoutes(len(LearnedRoutes.Entries()))
	UpstreamManager = upstream.New(Cfg.Upstreams, Cfg.UpstreamHealth)
	for _, state := range UpstreamManager.States() {
		ProxyMetrics.SetUpstreamState(state.Name, state.Health, state.Circuit)
	}
	if UpstreamManager.Enabled() {
		go monitorUpstreamHealth(context.Background())
	}
	log.Printf("Loaded %d learned domain routes", len(LearnedRoutes.Entries()))
	go maintainLearnedRoutes(ttl)

	if Cfg.Admin.Enabled() {
		if _, err := admin.Start(Cfg.Admin, ProxyMetrics, LearnedRoutes, UpstreamManager, ttl); err != nil {
			log.Fatalf("Failed to start admin server: %v", err)
		}
		log.Printf("Admin dashboard started on http://%s:%d/", Cfg.Admin.Address, Cfg.Admin.Port)
	}

	if Cfg.FakeSni.Interface != "" {
		okCapture, err, chCapture := setupCapture(context.Background(), Cfg.FakeSni.Interface)
		if okCapture {
			go TrackSessions(chCapture)
		}
		if err != nil {
			log.Printf("Traffic capture '%s' error: %v\n", Cfg.FakeSni.Interface, err)
		}
	}

	portStr := fmt.Sprintf("%s:%d", Cfg.Proxy.Address, Cfg.Proxy.Port)
	listener, err := net.Listen("tcp", portStr)
	if err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
	defer listener.Close()

	log.Printf("SOCKS5 proxy started on %v", portStr)
	//log.Printf("Fragmentation: first %d bytes in %d-byte chunks", initialFragSize, fragmentSize)

	var CntNo uint32 = 1
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("[%d] AcceptConnection error: %v", CntNo, err)
			continue
		}

		//log.Printf("[%d] New connection from: %s", CntNo, conn.RemoteAddr())
		inst := Socks5{
			clientConn:    conn,
			UniqNo:        CntNo,
			firstResponse: make(chan struct{}),
		}
		CntNo++
		go inst.AcceptConnection()
	}
}

func monitorUpstreamHealth(ctx context.Context) {
	check := func() {
		for _, state := range UpstreamManager.CheckAll(ctx) {
			ProxyMetrics.SetUpstreamState(state.Name, state.Health, state.Circuit)
			result := "health_check_success"
			if state.Health != "healthy" {
				result = "health_check_failure"
				log.Printf("Upstream health check failed name=%s circuit=%s failures=%d error=%s", state.Name, state.Circuit, state.ConsecutiveFailures, state.LastError)
			}
			ProxyMetrics.UpstreamResult(state.Name, result)
		}
	}
	check()
	ticker := time.NewTicker(Cfg.UpstreamHealth.CheckInterval())
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			check()
		}
	}
}

func maintainLearnedRoutes(ttl time.Duration) {
	flushTicker := time.NewTicker(30 * time.Second)
	pruneTicker := time.NewTicker(time.Hour)
	defer flushTicker.Stop()
	defer pruneTicker.Stop()
	for {
		select {
		case <-flushTicker.C:
			if err := LearnedRoutes.Flush(); err != nil {
				log.Printf("Error flushing learned domain usage: %v", err)
			}
		case <-pruneTicker.C:
			removed, err := LearnedRoutes.PruneExpired(ttl, time.Now())
			if err != nil {
				log.Printf("Error pruning learned domains: %v", err)
				continue
			}
			if removed > 0 {
				log.Printf("Pruned %d expired learned domain routes", removed)
			}
			ProxyMetrics.SetLearnedRoutes(len(LearnedRoutes.Entries()))
		}
	}
}
