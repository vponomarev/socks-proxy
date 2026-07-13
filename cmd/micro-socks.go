package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"

	"github.com/google/gopacket"
	"github.com/vponomarev/socks-proxy/internal/config"
	"github.com/vponomarev/socks-proxy/internal/routing"
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
	RSB           RingSessionBuffer
	SerSentBuffer chan gopacket.SerializeBuffer
	paramTTL      = flag.Int("ttl", 7, "TTL for fake packets")
	configPath    = flag.String("config", "proxy.yml", "Path to config file, default `proxy.yml`")
	Cfg           *config.Config
	LearnedRoutes *routing.Store
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
	log.Printf("Loaded %d learned domain routes", len(LearnedRoutes.Entries()))

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
