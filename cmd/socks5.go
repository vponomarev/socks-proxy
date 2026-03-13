package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/vponomarev/socks-proxy/internal/libtls"
)

var (
	ReplaceCounter NumReplaced
)

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

	// Аутентификация SOCKS5
	if err := s.AuthRequest(); err != nil {
		log.Printf("[%d] Authentication failed: %v", s.UniqNo, err)
		return
	}

	// Обработка запроса SOCKS5
	err := s.ProcessRequest()
	if err != nil {
		log.Printf("[%d] Request failed [%s:%d :%v]: %v", s.UniqNo, s.TargetHost, s.TargetPort, s.IsTargetIP, err)
		return
	}
	defer s.targetConn.Close()

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
	targetAddr := fmt.Sprintf("%s:%d", host, port)
	targetConn, err := net.Dial("tcp", targetAddr)
	if err != nil {
		// Отправляем ошибку клиенту
		response := []byte{socksVersion, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
		s.clientConn.Write(response)
		return err
	}

	// Отправляем успешный ответ
	localAddr := targetConn.LocalAddr().(*net.TCPAddr)
	response := make([]byte, 10)
	response[0] = socksVersion
	response[1] = 0x00 // Success
	response[2] = 0x00 // Reserved
	response[3] = 0x01 // IPv4
	copy(response[4:8], localAddr.IP.To4())
	binary.BigEndian.PutUint16(response[8:10], uint16(localAddr.Port))

	if _, err := s.clientConn.Write(response); err != nil {
		targetConn.Close()
		return err
	}

	s.targetConn = targetConn
	s.ConnTargetIP = s.targetConn.RemoteAddr().(*net.TCPAddr).IP.String()
	s.connectedAt = time.Now()

	log.Printf("[%d][%s] [%s => %s] CONNECT to: %s:%v",
		s.UniqNo,
		s.clientConn.RemoteAddr().String(),
		s.targetConn.LocalAddr().String(),
		s.targetConn.RemoteAddr().String(),
		s.TargetHost, s.TargetPort)
	return nil
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
		if err != nil {
			if err != io.EOF {
				//log.Printf("[%d] Read error [reverse]: %v", s.UniqNo, err)
			} else {
				//log.Printf("[%d][rev] bytes: %v", s.UniqNo, cntBytes)
			}
			break
		}

		if _, err := s.clientConn.Write(buffer[0:n]); err != nil {
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
					if hostname == "example-site.ru" {
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
