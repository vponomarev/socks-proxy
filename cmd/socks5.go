package main

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/vponomarev/socks-proxy/internal/config"
	"github.com/vponomarev/socks-proxy/internal/libtls"
	"github.com/vponomarev/socks-proxy/internal/socksclient"
	"github.com/vponomarev/socks-proxy/internal/upstream"
)

var (
	ReplaceCounter NumReplaced
	FallbackProbes = newProbeCoordinator()
	directDial     = func(network, address string, timeout time.Duration) (net.Conn, error) {
		return (&net.Dialer{Timeout: timeout}).Dial(network, address)
	}
)

type probeCoordinator struct {
	mu     sync.Mutex
	active map[string]struct{}
}

func newProbeCoordinator() *probeCoordinator {
	return &probeCoordinator{active: make(map[string]struct{})}
}

func (p *probeCoordinator) Start(host string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, exists := p.active[host]; exists {
		return false
	}
	p.active[host] = struct{}{}
	return true
}

func (p *probeCoordinator) Done(host string) {
	p.mu.Lock()
	delete(p.active, host)
	p.mu.Unlock()
}

type Socks5 struct {
	UniqNo uint32

	TargetHost string
	TargetPort uint16
	IsTargetIP bool

	ConnTargetIP string

	connectedAt time.Time

	clientConn net.Conn
	targetConn net.Conn

	bytesTX int
	bytesRX int

	Policy        config.ResolvedPolicy
	firstResponse chan struct{}
	responseOnce  sync.Once
	sync.RWMutex
}

type NumReplaced struct {
	Num int
	sync.RWMutex
}

func (n *NumReplaced) Add(num int) {
	n.Lock()
	defer n.Unlock()
	n.Num += num
}

func (n *NumReplaced) Get() int {
	n.RLock()
	defer n.RUnlock()
	return n.Num
}

func (s *Socks5) AcceptConnection() {
	defer s.clientConn.Close()
	sessionStarted := time.Now()
	sessionResult := "failed"
	if ProxyMetrics != nil {
		ProxyMetrics.SessionStarted()
		defer func() {
			tx, rx := s.GetMetrics()
			ProxyMetrics.SessionFinished(tx, rx, time.Since(sessionStarted), s.Policy.Egress, sessionResult)
		}()
	}
	if s.firstResponse == nil {
		s.firstResponse = make(chan struct{})
	}

	// Аутентификация SOCKS5
	if err := s.AuthRequest(); err != nil {
		log.Printf("[%d] Authentication failed: %v", s.UniqNo, err)
		return
	}

	// Обработка запроса SOCKS5
	err := s.ProcessRequest()
	if err != nil {
		if errors.Is(err, io.EOF) {
			return
		}
		log.Printf("[%d] Request failed [%s:%d :%v]: %v", s.UniqNo, s.TargetHost, s.TargetPort, s.IsTargetIP, err)
		return
	}
	defer s.targetConn.Close()
	sessionResult = "completed"

	// Start packet processing
	go s.StreamForward()
	s.StreamReverse()

	// Finalize metrics
	tx, rx := s.GetMetrics()
	duration := time.Since(s.connectedAt)
	if (tx == 0) || (rx > 0) {
		log.Printf("[%d] Sent=%d, Received=%d (during %v sec) (%s:%v) (%s)\n", s.UniqNo, tx, rx, duration.Seconds(), s.TargetHost, s.TargetPort, s.ConnTargetIP)
	} else {
		log.Printf("[%d] Sent=%d, Received=%d (during %v sec) (%s:%v) (%s) [BLOCK-CANDIDATE]\n", s.UniqNo, tx, rx, duration.Seconds(), s.TargetHost, s.TargetPort, s.ConnTargetIP)
	}
}

func (s *Socks5) AuthRequest() error {
	// Читаем методы аутентификации
	header := make([]byte, 2)
	if _, err := io.ReadFull(s.clientConn, header); err != nil {
		return err
	}

	if header[0] != socksVersion {
		return fmt.Errorf("unsupported SOCKS version: %d", header[0])
	}

	nMethods := header[1]
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(s.clientConn, methods); err != nil {
		return err
	}

	// Поддерживаем только NO AUTH
	noAuth := false
	for _, method := range methods {
		if method == 0 {
			noAuth = true
			break
		}
	}
	if !noAuth {
		s.clientConn.Write([]byte{socksVersion, 0xff})
		return fmt.Errorf("client did not offer NO AUTH")
	}

	response := []byte{socksVersion, 0}
	_, err := s.clientConn.Write(response)
	return err
}

func (s *Socks5) ProcessRequest() error {
	request := make([]byte, 4)
	if _, err := io.ReadFull(s.clientConn, request); err != nil {
		return err
	}

	if request[0] != socksVersion {
		return fmt.Errorf("unsupported SOCKS version: %d", request[0])
	}
	if request[1] != 0x01 {
		return fmt.Errorf("unsupported SOCKS command: %d", request[1])
	}
	if request[2] != 0x00 {
		return fmt.Errorf("invalid reserved byte: %d", request[2])
	}

	// Читаем адрес назначения
	var host string
	var port uint16

	switch request[3] {
	case 0x01: // IPv4
		ip := make([]byte, 4)
		if _, err := io.ReadFull(s.clientConn, ip); err != nil {
			return err
		}
		host = net.IP(ip).String()
		s.TargetHost = host
		s.IsTargetIP = true
	case 0x03: // Domain name
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(s.clientConn, lenBuf); err != nil {
			return err
		}
		domain := make([]byte, lenBuf[0])
		if _, err := io.ReadFull(s.clientConn, domain); err != nil {
			return err
		}
		host = string(domain)
		s.TargetHost = host
	case 0x04: // IPv6
		return fmt.Errorf("IPv6 not supported")
	default:
		return fmt.Errorf("unsupported address type: %d", request[3])
	}

	// Читаем порт
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(s.clientConn, portBuf); err != nil {
		return err
	}
	port = binary.BigEndian.Uint16(portBuf)
	s.TargetPort = uint16(port)

	if s.TargetHost == "0.0.0.0" {
		// Отправляем ошибку клиенту
		response := []byte{socksVersion, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
		s.clientConn.Write(response)
		return fmt.Errorf("forbidden connect to %v", s.TargetHost)
	}

	// Устанавливаем соединение с целевым сервером
	learnedUpstream := ""
	if LearnedRoutes != nil {
		if learned, ok := LearnedRoutes.LookupActive(s.TargetHost, Cfg.Detection.LearnedTTL(), time.Now()); ok {
			learnedUpstream = learned.Upstream
		}
	}
	s.Policy = Cfg.PolicyFor(s.TargetHost, learnedUpstream)

	var targetConn net.Conn
	var err error
	dialStarted := time.Now()
	if s.Policy.Egress == "socks5" {
		targetConn, err = dialUpstream(s.Policy.Upstream, host, port)
	} else {
		targetAddr := net.JoinHostPort(host, strconv.Itoa(int(port)))
		targetConn, err = directDial("tcp", targetAddr, 10*time.Second)
	}
	if ProxyMetrics != nil {
		result := "success"
		if err != nil {
			result = "failure"
		}
		ProxyMetrics.ObserveDial(s.Policy.Egress, s.Policy.Upstream, result, time.Since(dialStarted))
	}
	if err != nil && s.Policy.Egress == "direct" && s.Policy.Fallback != "" && s.Policy.Fallback != "none" {
		targetConn, err = s.connectAfterDirectFailure(host, port, err)
	}
	if err != nil {
		// Отправляем ошибку клиенту
		response := []byte{socksVersion, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
		s.clientConn.Write(response)
		return err
	}

	// Отправляем успешный ответ
	response := successReply(targetConn.LocalAddr())

	if _, err := s.clientConn.Write(response); err != nil {
		targetConn.Close()
		return err
	}

	s.targetConn = targetConn
	s.ConnTargetIP = s.targetConn.RemoteAddr().(*net.TCPAddr).IP.String()
	s.connectedAt = time.Now()
	if ProxyMetrics != nil {
		ProxyMetrics.RouteDecision(s.Policy.Name, s.Policy.Egress, s.Policy.Upstream)
	}
	if s.Policy.Name == "learned-domain" && LearnedRoutes != nil {
		LearnedRoutes.MarkUsed(s.TargetHost, time.Now())
	}

	log.Printf("[%d][%s] [%s => %s] CONNECT to: %s:%v policy=%s egress=%s upstream=%s dpi=%s",
		s.UniqNo,
		s.clientConn.RemoteAddr().String(),
		s.targetConn.LocalAddr().String(),
		s.targetConn.RemoteAddr().String(),
		s.TargetHost, s.TargetPort, s.Policy.Name, s.Policy.Egress, s.Policy.Upstream, s.Policy.DPI)
	return nil
}

func dialUpstream(name, host string, port uint16) (net.Conn, error) {
	cfgUpstream, ok := Cfg.Upstreams[name]
	if !ok {
		return nil, fmt.Errorf("unknown SOCKS5 upstream %q", name)
	}
	if UpstreamManager != nil && !UpstreamManager.Allow(name) {
		if ProxyMetrics != nil {
			ProxyMetrics.UpstreamResult(name, "circuit_rejected")
			if state, exists := UpstreamManager.State(name); exists {
				ProxyMetrics.SetUpstreamState(name, state.Health, state.Circuit)
			}
		}
		return nil, fmt.Errorf("upstream %s: %w", name, upstream.ErrCircuitOpen)
	}
	ctx, cancel := context.WithTimeout(context.Background(), cfgUpstream.Timeout())
	defer cancel()
	conn, err := socksclient.Dial(ctx, cfgUpstream, host, port)
	if UpstreamManager != nil {
		state := UpstreamManager.Record(name, err)
		if ProxyMetrics != nil {
			result := "dial_success"
			if err != nil {
				result = "dial_failure"
			}
			ProxyMetrics.UpstreamResult(name, result)
			ProxyMetrics.SetUpstreamState(name, state.Health, state.Circuit)
		}
	}
	return conn, err
}

func (s *Socks5) connectAfterDirectFailure(host string, port uint16, directErr error) (net.Conn, error) {
	upstreamName := s.Policy.Fallback
	log.Printf("[%d] event=direct_connect_failed host=%s fallback=%s error=%v", s.UniqNo, host, upstreamName, directErr)
	if ProxyMetrics != nil {
		ProxyMetrics.FallbackResult("connect_failure_candidate", upstreamName)
	}

	started := time.Now()
	conn, fallbackErr := dialUpstream(upstreamName, host, port)
	if ProxyMetrics != nil {
		result := "success"
		if fallbackErr != nil {
			result = "failure"
		}
		ProxyMetrics.ObserveDial("socks5", upstreamName, result, time.Since(started))
	}
	if fallbackErr != nil {
		log.Printf("[%d] event=connect_fallback_failed host=%s upstream=%s error=%v", s.UniqNo, host, upstreamName, fallbackErr)
		if ProxyMetrics != nil {
			ProxyMetrics.FallbackResult("connect_failure_failed", upstreamName)
		}
		return nil, fmt.Errorf("direct connect failed: %v; fallback through %s failed: %w", directErr, upstreamName, fallbackErr)
	}

	s.Policy.Name = "connect-fallback"
	s.Policy.Egress = "socks5"
	s.Policy.DPI = "none"
	s.Policy.Upstream = upstreamName
	added := false
	if LearnedRoutes != nil {
		var learnErr error
		added, learnErr = LearnedRoutes.Add(host, upstreamName, "direct-connect-failure-upstream-success")
		if learnErr != nil {
			log.Printf("[%d] event=learned_domain_write_failed host=%s error=%v", s.UniqNo, host, learnErr)
			if ProxyMetrics != nil {
				ProxyMetrics.FallbackResult("learn_write_failed", upstreamName)
			}
		}
	}
	log.Printf("[%d] event=connect_fallback_success host=%s upstream=%s learned=%t", s.UniqNo, host, upstreamName, added)
	if ProxyMetrics != nil {
		ProxyMetrics.FallbackResult("connect_failure_success", upstreamName)
		if LearnedRoutes != nil {
			ProxyMetrics.SetLearnedRoutes(len(LearnedRoutes.Entries()))
		}
	}
	return conn, nil
}

func successReply(addr net.Addr) []byte {
	tcpAddr, ok := addr.(*net.TCPAddr)
	if !ok {
		return []byte{socksVersion, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	}
	if ip4 := tcpAddr.IP.To4(); ip4 != nil {
		response := []byte{socksVersion, 0, 0, 1, 0, 0, 0, 0, 0, 0}
		copy(response[4:8], ip4)
		binary.BigEndian.PutUint16(response[8:10], uint16(tcpAddr.Port))
		return response
	}
	response := make([]byte, 22)
	response[0], response[1], response[2], response[3] = socksVersion, 0, 0, 4
	copy(response[4:20], tcpAddr.IP.To16())
	binary.BigEndian.PutUint16(response[20:22], uint16(tcpAddr.Port))
	return response
}

func (s *Socks5) UpdateMetrics(tx, rx int) {
	s.Lock()
	s.bytesTX += tx
	s.bytesRX += rx
	s.Unlock()
}

func (s *Socks5) GetMetrics() (tx, rx int) {
	s.RLock()
	defer s.RUnlock()
	return s.bytesTX, s.bytesRX
}

func (s *Socks5) StreamReverse() {
	buffer := make([]byte, 32*1024) // 32KB buffer
	cntBytes := 0

	for {
		n, err := s.targetConn.Read(buffer)
		cntBytes += n
		s.UpdateMetrics(0, n)
		if n > 0 {
			s.responseOnce.Do(func() { close(s.firstResponse) })
		}
		if err != nil {
			if err != io.EOF {
				//log.Printf("[%d] Read error [reverse]: %v", s.UniqNo, err)
			} else {
				//log.Printf("[%d][rev] bytes: %v", s.UniqNo, cntBytes)
			}
			break
		}

		if err := writeConn(s.clientConn, buffer[0:n]); err != nil {
			//log.Printf("[%d] Write error [reverse]: %v", s.UniqNo, err)
			break
		}
	}
}

func (s *Socks5) DoInject(data []byte) {
	// Inject fake packets
	// if (s.TargetHost == "i.ytimg.com" || (s.TargetHost == "vpnc.ru")) && s.TargetPort == 443 {
	ok, rName := Cfg.IsFakeStrategy(s.TargetHost)
	if ok && s.TargetPort == 443 {
		time.Sleep(30 * time.Millisecond)
		if ok, si := CaptureSessionInfo(s.targetConn); ok {
			// fmt.Println("** captured ISN: ", si.ISN)

			ln := len(data)
			if ln > 1024 {
				ln = 1024
			}

			haveSNI, sni, offset := libtls.DecodeSSLHandshake(data)

			// Заменить последний символ доменного имени
			if haveSNI {
				fp := append([]byte(nil), data[0:ln]...)
				// fmt.Printf(rName)
				copy(fp[offset:offset+len(sni)], []byte(rName))
				//if ln > offset+len(sni) {
				//	fp[offset+len(sni)-1] = 'x'
				//}
				err, pkt := PrepareFakePacket(si, uint8(*paramTTL), fp)
				if err == nil {
					SerSentBuffer <- pkt

					log.Printf("[%d] Injected FAKE packet (%d bytes)", s.UniqNo, len(data))
					time.Sleep(30 * time.Millisecond)
				} else {
					fmt.Println("Error generating packet", err)
				}
			} else {
				fmt.Printf("[%d] No SNI found in first packet\n", s.UniqNo)
			}
		} else {
			fmt.Printf("[%d] No session tracking found\n", s.UniqNo)
		}
	}
}

func (s *Socks5) StreamForward() {
	defer s.targetConn.Close()
	buffer := make([]byte, 32*1024)
	fragmenter := NewFragmenter(initialFragSize)
	tlsBuffer := make([]byte, 0, 64*1024)
	inspectionDone := false
	probeStarted := false

	for {
		n, err := s.clientConn.Read(buffer)
		if n > 0 {
			data := buffer[:n]
			var candidate []byte
			candidateHost := ""

			if !inspectionDone {
				if len(tlsBuffer)+n <= cap(tlsBuffer) {
					tlsBuffer = append(tlsBuffer, data...)
				} else {
					inspectionDone = true
				}
				if !inspectionDone && len(tlsBuffer) >= 5 {
					if tlsBuffer[0] != 0x16 {
						inspectionDone = true
					} else {
						recordLength := 5 + int(binary.BigEndian.Uint16(tlsBuffer[3:5]))
						if len(tlsBuffer) >= recordLength {
							recordData := append([]byte(nil), tlsBuffer[:recordLength]...)
							tlsRecord, decodeErr := libtls.DecodeTLS(recordData)
							if decodeErr == nil {
								_, sni := tlsRecord.Message.FindSNI()
								candidateHost = s.TargetHost
								if s.IsTargetIP && sni != "" {
									candidateHost = sni
								}
								log.Printf("[%d] event=tls_client_hello target=%s sni=%s", s.UniqNo, s.TargetHost, sni)
								if s.Policy.DPI == "fake-sni" {
									s.injectFakePacket(tlsRecord)
								}
								if s.Policy.Egress == "direct" && s.Policy.Fallback != "" && s.Policy.Fallback != "none" {
									candidate = recordData
								}
							}
							inspectionDone = true
						}
					}
				}
			}

			var writeErr error
			if s.Policy.DPI == "fragment" && fragmenter.ShouldFragment() {
				writeErr = fragmenter.WriteFragmented(s.targetConn, data)
			} else {
				writeErr = writeConn(s.targetConn, data)
			}
			s.UpdateMetrics(n, 0)
			if writeErr != nil {
				break
			}
			if len(candidate) > 0 && candidateHost != "" && !probeStarted {
				probeStarted = true
				go s.monitorBlockCandidate(candidateHost, candidate)
			}
		}
		if err != nil {
			break
		}
	}
}

func (s *Socks5) injectFakePacket(tlsRecord *libtls.TLSRecord) {
	if SerSentBuffer == nil || s.TargetPort != 443 {
		return
	}
	ok, hostname := tlsRecord.Message.FindSNI()
	if !ok || hostname == "" {
		return
	}
	decoyName := hostname[:len(hostname)-1] + "x"
	tlsRecord.Message.ReplaceSNI(decoyName)
	data, err := tlsRecord.EncodeTLS()
	if err != nil {
		log.Printf("[%d] event=fake_sni_encode_failed error=%v", s.UniqNo, err)
		return
	}

	time.Sleep(30 * time.Millisecond)
	ok, session := CaptureSessionInfo(s.targetConn)
	if !ok {
		log.Printf("[%d] event=fake_sni_session_not_found", s.UniqNo)
		return
	}
	ttl := Cfg.FakeSni.Ttl
	if ttl == 0 {
		ttl = *paramTTL
	}
	ttl = s.Policy.TTL(ttl)
	err, packet := PrepareFakePacket(session, uint8(ttl), data)
	if err != nil {
		log.Printf("[%d] event=fake_sni_packet_failed error=%v", s.UniqNo, err)
		return
	}
	SerSentBuffer <- packet
	log.Printf("[%d] event=fake_sni_injected bytes=%d ttl=%d", s.UniqNo, len(data), ttl)
	time.Sleep(30 * time.Millisecond)
}

func (s *Socks5) monitorBlockCandidate(host string, clientHello []byte) {
	timer := time.NewTimer(Cfg.Detection.ResponseTimeout())
	defer timer.Stop()
	select {
	case <-s.firstResponse:
		return
	case <-timer.C:
	}
	if !FallbackProbes.Start(host) {
		log.Printf("[%d] event=fallback_probe_skipped reason=already_in_progress host=%s", s.UniqNo, host)
		if ProxyMetrics != nil {
			ProxyMetrics.FallbackResult("skipped_in_progress", s.Policy.Fallback)
		}
		return
	}
	defer FallbackProbes.Done(host)

	log.Printf("[%d] event=block_candidate host=%s target_ip=%s fallback=%s", s.UniqNo, host, s.ConnTargetIP, s.Policy.Fallback)
	if ProxyMetrics != nil {
		ProxyMetrics.FallbackResult("block_candidate", s.Policy.Fallback)
	}
	upstream, ok := Cfg.Upstreams[s.Policy.Fallback]
	if !ok {
		log.Printf("[%d] event=fallback_configuration_error upstream=%s", s.UniqNo, s.Policy.Fallback)
		if ProxyMetrics != nil {
			ProxyMetrics.FallbackResult("configuration_error", s.Policy.Fallback)
		}
		return
	}
	probeTimeout := Cfg.Detection.FallbackProbeTimeout()
	ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
	defer cancel()
	probeConn, err := socksclient.Dial(ctx, upstream, s.TargetHost, s.TargetPort)
	if err != nil {
		log.Printf("[%d] event=fallback_connect_failed host=%s upstream=%s error=%v", s.UniqNo, host, s.Policy.Fallback, err)
		if ProxyMetrics != nil {
			ProxyMetrics.FallbackResult("connect_failed", s.Policy.Fallback)
		}
		return
	}
	defer probeConn.Close()
	if err := probeConn.SetDeadline(time.Now().Add(probeTimeout)); err != nil {
		return
	}
	if err := writeConn(probeConn, clientHello); err != nil {
		log.Printf("[%d] event=fallback_write_failed host=%s upstream=%s error=%v", s.UniqNo, host, s.Policy.Fallback, err)
		if ProxyMetrics != nil {
			ProxyMetrics.FallbackResult("write_failed", s.Policy.Fallback)
		}
		return
	}
	response := make([]byte, 1)
	if _, err := io.ReadFull(probeConn, response); err != nil {
		log.Printf("[%d] event=fallback_probe_failed host=%s upstream=%s error=%v", s.UniqNo, host, s.Policy.Fallback, err)
		if ProxyMetrics != nil {
			ProxyMetrics.FallbackResult("probe_failed", s.Policy.Fallback)
		}
		return
	}
	select {
	case <-s.firstResponse:
		log.Printf("[%d] event=fallback_ignored reason=direct_response_received host=%s", s.UniqNo, host)
		if ProxyMetrics != nil {
			ProxyMetrics.FallbackResult("direct_won", s.Policy.Fallback)
		}
		return
	default:
	}

	added, err := LearnedRoutes.Add(host, s.Policy.Fallback, "direct-timeout-upstream-success")
	if err != nil {
		log.Printf("[%d] event=learned_domain_write_failed host=%s error=%v", s.UniqNo, host, err)
		if ProxyMetrics != nil {
			ProxyMetrics.FallbackResult("learn_write_failed", s.Policy.Fallback)
		}
		return
	}
	log.Printf("[%d] event=fallback_success host=%s upstream=%s learned=%t", s.UniqNo, host, s.Policy.Fallback, added)
	if ProxyMetrics != nil {
		ProxyMetrics.FallbackResult("success", s.Policy.Fallback)
		ProxyMetrics.SetLearnedRoutes(len(LearnedRoutes.Entries()))
	}
	// The browser performs the retry. Closing both sides makes the failed
	// attempt finish promptly; the next connection uses the learned upstream.
	s.targetConn.Close()
	s.clientConn.Close()
}

func writeConn(conn net.Conn, data []byte) error {
	for len(data) > 0 {
		n, err := conn.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrUnexpectedEOF
		}
		data = data[n:]
	}
	return nil
}

func (s *Socks5) streamForwardLegacy() {
	buffer := make([]byte, 32*1024) // 32KB buffer
	cntBytes := 0

	for {
		n, err := s.clientConn.Read(buffer)

		flagReplace := false
		if cntBytes == 0 && n > 0 && err == nil {
			//s.DoInject(buffer[0:n])
			tls, err := libtls.DecodeTLS(buffer)
			// Process ONLY if TLS was decoded and packet contains only TLS part
			if err == nil && (tls.Length+5) == uint16(n) {
				ok, hostname := tls.Message.FindSNI()
				if ok {
					fmt.Printf("TLS SNI Hostname: %v\n", hostname)
					if false {
						//tls.Message.ReplaceSNI("example-site.rx")
						tls.Message.RemoveSNI()

						// In case of any SNI modification
						//eok := tls.Message.RemoveExtensionByType(libtls.TLS_EXTENSION_ECH)
						//if eok {
						//	fmt.Println("Removed ECH")
						//}
						tls.Message.RemoveExtensionByType(libtls.TLS_EXTENSION_KEY_SHARE)
						tls.Message.RemoveExtensionByType(13)

						// Decode key share
						if eok, eid, _ := tls.Message.FindExtension(libtls.TLS_EXTENSION_KEY_SHARE); eok && false {
							ks, e := tls.Message.Extensions[eid].DecodeKeyShare()
							if e == nil {
								//ks.RemoveExtensionByType(libtls.TLS_KEY_SHARE_X25519MLKEM768)
								ok, he := ks.Encode()
								if ok {
									tls.Message.Extensions[eid] = he
								}
							}
							//fmt.Println(e, ks)
						}

						if ReplaceCounter.Get()%2 == 0 {
							flagReplace = true
						}
						fmt.Printf("### REPLACE COUNTER: %v (%v)\n", ReplaceCounter.Get(), flagReplace)
						ReplaceCounter.Add(1)
					}
				}

				if flagReplace {
					d, e := tls.EncodeTLS()
					if e != nil {
						fmt.Printf("# Error encoding TLS: %v\n", e)
					} else {
						fmt.Printf("Recreate TLS handshake: %v => %v bytes\n", n, len(d))
						s1 := hex.EncodeToString(buffer[0:n])
						s2 := hex.EncodeToString(d)
						fmt.Println(s1)
						fmt.Println(s2)
						copy(buffer, d)
						n = len(d)
					}
				}
			}
		}

		cntBytes += n
		s.UpdateMetrics(n, 0)
		if err != nil {
			if err != io.EOF {
				//log.Printf("[%d] Read error [fwd]: %v", s.UniqNo, err)
			} else {
				//log.Printf("[%d][fwd] bytes: %v", s.UniqNo, cntBytes)
			}
			break
		}

		if _, err := s.targetConn.Write(buffer[0:n]); err != nil {
			//log.Printf("[%d] Write error [fwd]: %v", s.UniqNo, err)
			break
		}
	}
}

func forwardWithFragmentation(src, dst net.Conn, direction string) {
	buffer := make([]byte, 32*1024) // 32KB buffer
	fragmenter := NewFragmenter(initialFragSize)

	// wait for 30 ms
	time.Sleep(30 * time.Millisecond)

	//ok, si := CaptureSessionInfo(src, dst)
	//if ok && false {
	//	fmt.Println("** captured ISN: ", si.ISN)
	//
	//	if si.DstPort == 443 {
	//		err, pkt := PrepareFakePacket(si, uint8(*paramTTL), []byte("GET / HTTP/1.0\nHost: www.gosuslugi.ru\n\n"))
	//		if err == nil {
	//			SerSentBuffer <- pkt
	//
	//			time.Sleep(30 * time.Millisecond)
	//		} else {
	//			fmt.Println("Error generating packet", err)
	//		}
	//
	//	}
	//}

	for {
		n, err := src.Read(buffer)
		if err != nil {
			if err != io.EOF {
				log.Printf("Read error (%s): %v", direction, err)
			}
			break
		}

		if n > 0 {
			data := buffer[:n]

			if fragmenter.ShouldFragment() {
				// Используем фрагментацию
				if err := fragmenter.WriteFragmented(dst, data); err != nil {
					log.Printf("Write fragmented error (%s): %v", direction, err)
					break
				}
			} else {
				// Обычная отправка
				if _, err := dst.Write(data); err != nil {
					log.Printf("Write error (%s): %v", direction, err)
					break
				}
			}
		}
	}
}

func NewFragmenter(totalLimit int) *Fragmenter {
	return &Fragmenter{
		enabled:    true,
		sentBytes:  0,
		totalLimit: totalLimit,
	}
}

func (f *Fragmenter) ShouldFragment() bool {
	return f.enabled && f.sentBytes < f.totalLimit
}

func (f *Fragmenter) WriteFragmented(conn net.Conn, data []byte) error {
	totalWritten := 0

	for totalWritten < len(data) && f.ShouldFragment() {
		chunkSize := fragmentSize
		remaining := f.totalLimit - f.sentBytes

		if chunkSize > remaining {
			chunkSize = remaining
		}

		if totalWritten+chunkSize > len(data) {
			chunkSize = len(data) - totalWritten
		}

		if chunkSize == 0 {
			break
		}

		chunk := data[totalWritten : totalWritten+chunkSize]
		n, err := conn.Write(chunk)
		if err != nil {
			return err
		}

		// Искусственная задержка между фрагментами
		time.Sleep(10 * time.Millisecond)

		totalWritten += n
		f.sentBytes += n

		// log.Printf("Sent fragment: %d bytes (total fragmented: %d/%d)",
		//	n, f.sentBytes, f.totalLimit)
	}

	// Если остались данные после фрагментации, отправляем обычным способом
	if totalWritten < len(data) {
		f.enabled = false // Отключаем фрагментацию
		remaining := data[totalWritten:]
		_, err := conn.Write(remaining)
		if err != nil {
			return err
		}
		log.Printf("Sent remaining %d bytes without fragmentation", len(remaining))
	}

	return nil
}
