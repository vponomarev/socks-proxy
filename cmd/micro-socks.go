package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
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
	SessionWG       sync.WaitGroup
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
	appCtx, appCancel := context.WithCancel(context.Background())

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
	runtime := installRuntime(appCtx, Cfg)
	UpstreamManager = runtime.upstreams
	log.Printf("Loaded %d learned domain routes", len(LearnedRoutes.Entries()))
	go maintainLearnedRoutes(appCtx)

	var adminServer *http.Server
	if Cfg.Admin.Enabled() {
		upstreamProvider := func() *upstream.Manager { return currentRuntime().upstreams }
		ttlProvider := func() time.Duration { return currentRuntime().config.Detection.LearnedTTL() }
		reload := func() error {
			if err := reloadRuntime(appCtx, *configPath); err != nil {
				return err
			}
			log.Printf("Configuration reloaded from %s", *configPath)
			return nil
		}
		adminServer, err = admin.Start(Cfg.Admin, ProxyMetrics, LearnedRoutes, upstreamProvider, ttlProvider, reload)
		if err != nil {
			log.Fatalf("Failed to start admin server: %v", err)
		}
		log.Printf("Admin dashboard started on http://%s:%d/", Cfg.Admin.Address, Cfg.Admin.Port)
	}

	if Cfg.FakeSni.Interface != "" {
		okCapture, err, chCapture := setupCapture(appCtx, Cfg.FakeSni.Interface)
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

	shutdownCh := make(chan os.Signal, 1)
	signal.Notify(shutdownCh, shutdownSignals()...)
	defer signal.Stop(shutdownCh)
	shuttingDown := make(chan struct{})
	go func() {
		sig := <-shutdownCh
		log.Printf("Shutdown signal received: %v", sig)
		close(shuttingDown)
		_ = listener.Close()
	}()
	go watchReloadSignals(appCtx)

	var CntNo uint32 = 1
	accepting := true
	for accepting {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-shuttingDown:
				accepting = false
				continue
			default:
			}
			log.Printf("[%d] AcceptConnection error: %v", CntNo, err)
			continue
		}

		//log.Printf("[%d] New connection from: %s", CntNo, conn.RemoteAddr())
		inst := Socks5{
			clientConn:    conn,
			UniqNo:        CntNo,
			firstResponse: make(chan struct{}),
			runtime:       currentRuntime(),
		}
		CntNo++
		SessionWG.Add(1)
		go func() {
			defer SessionWG.Done()
			inst.AcceptConnection()
		}()
	}
	gracefulShutdown(appCancel, adminServer)
}

func monitorUpstreamHealth(ctx context.Context, runtime *proxyRuntime) {
	check := func() {
		for _, state := range runtime.upstreams.CheckAll(ctx) {
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
	ticker := time.NewTicker(runtime.config.UpstreamHealth.CheckInterval())
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

func maintainLearnedRoutes(ctx context.Context) {
	flushTicker := time.NewTicker(30 * time.Second)
	pruneTicker := time.NewTicker(time.Hour)
	defer flushTicker.Stop()
	defer pruneTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-flushTicker.C:
			if err := LearnedRoutes.Flush(); err != nil {
				log.Printf("Error flushing learned domain usage: %v", err)
			}
		case <-pruneTicker.C:
			ttl := currentRuntime().config.Detection.LearnedTTL()
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

func watchReloadSignals(ctx context.Context) {
	signals := reloadSignals()
	if len(signals) == 0 {
		return
	}
	reloadCh := make(chan os.Signal, 1)
	signal.Notify(reloadCh, signals...)
	defer signal.Stop(reloadCh)
	for {
		select {
		case <-ctx.Done():
			return
		case sig := <-reloadCh:
			if err := reloadRuntime(ctx, *configPath); err != nil {
				log.Printf("Configuration reload failed after %v: %v", sig, err)
			} else {
				log.Printf("Configuration reloaded from %s after %v", *configPath, sig)
			}
		}
	}
}

func gracefulShutdown(cancel context.CancelFunc, adminServer *http.Server) {
	timeout := currentRuntime().config.Proxy.GracefulTimeout()
	ctx, stop := context.WithTimeout(context.Background(), timeout)
	defer stop()
	cancel()
	stopRuntimeHealth()

	if adminServer != nil {
		if err := adminServer.Shutdown(ctx); err != nil && !errors.Is(err, context.DeadlineExceeded) {
			log.Printf("Admin shutdown error: %v", err)
		}
	}
	if waitForWaitGroup(ctx, &SessionWG) {
		log.Printf("All active proxy sessions completed")
	} else {
		log.Printf("Graceful shutdown timeout reached with active sessions")
	}
	if err := LearnedRoutes.Flush(); err != nil {
		log.Printf("Final learned-domain flush failed: %v", err)
	}
}

func waitForWaitGroup(ctx context.Context, wg *sync.WaitGroup) bool {
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-ctx.Done():
		return false
	}
}
