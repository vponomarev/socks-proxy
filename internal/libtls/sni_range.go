package libtls

import (
	"encoding/binary"
	"fmt"
)

// ClientHelloSNIRange returns the byte range occupied by the first DNS SNI
// name in a complete TLS ClientHello record. Returned offsets are relative to
// the beginning of data and are suitable split points for ordinary TCP writes.
func ClientHelloSNIRange(data []byte) (int, int, error) {
	if len(data) < 9 || data[0] != 0x16 {
		return 0, 0, fmt.Errorf("not a TLS handshake record")
	}
	recordEnd := 5 + int(binary.BigEndian.Uint16(data[3:5]))
	if recordEnd > len(data) {
		return 0, 0, fmt.Errorf("incomplete TLS record")
	}
	if data[5] != 0x01 {
		return 0, 0, fmt.Errorf("not a ClientHello")
	}
	handshakeLength := int(data[6])<<16 | int(data[7])<<8 | int(data[8])
	handshakeEnd := 9 + handshakeLength
	if handshakeEnd > recordEnd {
		return 0, 0, fmt.Errorf("incomplete ClientHello")
	}

	offset := 9 + 2 + 32 // handshake header, version and random
	var ok bool
	if offset, ok = skipVector8(data, offset, handshakeEnd); !ok { // session ID
		return 0, 0, fmt.Errorf("invalid ClientHello session ID")
	}
	if offset, ok = skipVector16(data, offset, handshakeEnd); !ok { // cipher suites
		return 0, 0, fmt.Errorf("invalid ClientHello cipher suites")
	}
	if offset, ok = skipVector8(data, offset, handshakeEnd); !ok { // compression
		return 0, 0, fmt.Errorf("invalid ClientHello compression methods")
	}
	if offset+2 > handshakeEnd {
		return 0, 0, fmt.Errorf("ClientHello has no extensions")
	}
	extensionsEnd := offset + 2 + int(binary.BigEndian.Uint16(data[offset:offset+2]))
	offset += 2
	if extensionsEnd > handshakeEnd {
		return 0, 0, fmt.Errorf("invalid ClientHello extensions length")
	}
	for offset+4 <= extensionsEnd {
		typ := binary.BigEndian.Uint16(data[offset : offset+2])
		length := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
		value := offset + 4
		next := value + length
		if next > extensionsEnd {
			return 0, 0, fmt.Errorf("invalid ClientHello extension length")
		}
		if typ == 0 {
			return serverNameRange(data, value, next)
		}
		offset = next
	}
	return 0, 0, fmt.Errorf("ClientHello has no SNI")
}

func skipVector8(data []byte, offset, limit int) (int, bool) {
	if offset >= limit {
		return 0, false
	}
	next := offset + 1 + int(data[offset])
	return next, next <= limit
}

func skipVector16(data []byte, offset, limit int) (int, bool) {
	if offset+2 > limit {
		return 0, false
	}
	next := offset + 2 + int(binary.BigEndian.Uint16(data[offset:offset+2]))
	return next, next <= limit
}

func serverNameRange(data []byte, offset, limit int) (int, int, error) {
	if offset+2 > limit {
		return 0, 0, fmt.Errorf("invalid SNI list")
	}
	listEnd := offset + 2 + int(binary.BigEndian.Uint16(data[offset:offset+2]))
	if listEnd > limit {
		return 0, 0, fmt.Errorf("invalid SNI list length")
	}
	offset += 2
	for offset+3 <= listEnd {
		nameType := data[offset]
		nameStart := offset + 3
		nameEnd := nameStart + int(binary.BigEndian.Uint16(data[offset+1:offset+3]))
		if nameEnd > listEnd {
			return 0, 0, fmt.Errorf("invalid SNI name length")
		}
		if nameType == 0 && nameEnd > nameStart {
			return nameStart, nameEnd, nil
		}
		offset = nameEnd
	}
	return 0, 0, fmt.Errorf("SNI has no DNS name")
}
