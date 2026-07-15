package libtls

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

// GenerateClientHello asks the standard library to create a self-consistent
// TLS ClientHello for the decoy SNI. Restricting key exchange to X25519 avoids
// oversized post-quantum key shares without rewriting a client's transcript.
func GenerateClientHello(serverName string, maxSize int) ([]byte, error) {
	if serverName == "" {
		return nil, fmt.Errorf("decoy SNI is empty")
	}
	clientSide, captureSide := net.Pipe()
	defer captureSide.Close()
	client := tls.Client(clientSide, &tls.Config{
		ServerName:             serverName,
		MinVersion:             tls.VersionTLS12,
		MaxVersion:             tls.VersionTLS13,
		CurvePreferences:       []tls.CurveID{tls.X25519},
		NextProtos:             []string{"h2", "http/1.1"},
		SessionTicketsDisabled: true,
	})
	done := make(chan error, 1)
	go func() {
		done <- client.Handshake()
		client.Close()
	}()
	deadline := time.Now().Add(2 * time.Second)
	if err := captureSide.SetDeadline(deadline); err != nil {
		return nil, err
	}
	header := make([]byte, 5)
	if _, err := io.ReadFull(captureSide, header); err != nil {
		return nil, fmt.Errorf("capture generated ClientHello header: %w", err)
	}
	if header[0] != 0x16 {
		return nil, fmt.Errorf("generated TLS record has content type 0x%02x", header[0])
	}
	recordLength := int(binary.BigEndian.Uint16(header[3:5]))
	data := make([]byte, 5+recordLength)
	copy(data, header)
	if _, err := io.ReadFull(captureSide, data[5:]); err != nil {
		return nil, fmt.Errorf("capture generated ClientHello body: %w", err)
	}
	captureSide.Close()
	<-done // The peer closure is the expected end of this synthetic handshake.
	if len(data) > maxSize {
		return nil, fmt.Errorf("generated ClientHello is %d bytes, limit is %d", len(data), maxSize)
	}
	if _, err := DecodeTLS(data); err != nil {
		return nil, fmt.Errorf("generated ClientHello is invalid: %w", err)
	}
	return data, nil
}
