package libtls

import (
	"encoding/binary"
	"fmt"
)

const (
	TLS_EXTENSION_KEY_SHARE = 51
	TLS_EXTENSION_ECH       = 65037
	TLS_EXTENSION_PADDING   = 21

	TLS_KEY_SHARE_X25519MLKEM768 = 4588
	TLS_KEY_SHARE_x25519         = 29
	TLS_KEK_SHARE_secp256r1      = 23
)

type HelloExtension struct {
	Type   uint16
	Length uint16
	Data   []byte
}
type ClientHello struct {
	Version               uint16
	Random                [32]byte
	SessionIDLen          uint8
	SessionID             []byte
	CipherSuitesLen       uint16
	CipherSuites          []uint16
	CompressionMethodsLen uint8
	CompressionMethods    []byte
	ExtensionsLength      uint16
	Extensions            []HelloExtension
}

type HandshakeHeader struct {
	MsgType uint8
	Length  uint32 // 3 bytes in network order
}

type TLSRecord struct {
	ContentType uint8  // 0x16 = Handshake, 0x17 = Application Data, etc
	Version     uint16 // TLS version (0x0303 for TLS 1.2, 0x0304 for TLS 1.3)
	Length      uint16
	Header      HandshakeHeader
	Message     ClientHello
}

func getNextExtension(data []byte, offset int) (out []byte, t int, newOffset int, isLast bool) {
	if len(data) < offset+4 {
		out = []byte{}
		t = -1
		newOffset += len(data)
		isLast = true
		return
	}

	t = int(data[offset+0])*256 + int(data[offset+1])
	l := int(data[offset+2])*256 + int(data[offset+3])

	if offset+l+4 > len(data) {
		out = data[offset+4:]
		isLast = true
		return
	}

	out = data[offset+4 : offset+4+l]
	newOffset = offset + 4 + l
	if newOffset >= len(data) {
		isLast = true
	}
	return
}

func DecodeTLS(data []byte) (record *TLSRecord, err error) {
	if len(data) < 5 {
		return nil, fmt.Errorf("data too short for TLS record")
	}

	record = &TLSRecord{
		ContentType: data[0],
		Version:     binary.BigEndian.Uint16(data[1:3]),
		Length:      binary.BigEndian.Uint16(data[3:5]),
		Header:      HandshakeHeader{},
		Message:     ClientHello{},
	}

	if record.ContentType != 0x16 { // Handshake
		return nil, fmt.Errorf("not a handshake record")
	}

	if len(data) < 5+int(record.Length) {
		return nil, fmt.Errorf("incomplete TLS record")
	}

	handshakeData := data[5 : 5+int(record.Length)] // Skip TLS record header

	// Parse Handshake Header
	if len(handshakeData) < 4 {
		return nil, fmt.Errorf("data too short for handshake header")
	}

	handshakeHeader := HandshakeHeader{
		MsgType: handshakeData[0],
		Length:  uint32(handshakeData[1])<<16 | uint32(handshakeData[2])<<8 | uint32(handshakeData[3]),
	}

	if handshakeHeader.MsgType != 0x01 { // ClientHello
		return nil, fmt.Errorf("not a ClientHello")
	}

	if len(handshakeData) < 4+int(handshakeHeader.Length) {
		return nil, fmt.Errorf("incomplete handshake message")
	}

	clientHelloData := handshakeData[4 : 4+int(handshakeHeader.Length)] // Skip handshake header
	offset := 0

	// Parse ClientHello
	hello := &ClientHello{}

	// Version (2 bytes)
	if offset+2 > len(clientHelloData) {
		return nil, fmt.Errorf("incomplete ClientHello version")
	}
	hello.Version = binary.BigEndian.Uint16(clientHelloData[offset:])
	offset += 2

	// Random (32 bytes)
	if offset+32 > len(clientHelloData) {
		return nil, fmt.Errorf("incomplete ClientHello random")
	}
	copy(hello.Random[:], clientHelloData[offset:offset+32])
	offset += 32

	// SessionID
	if offset+1 > len(clientHelloData) {
		return nil, fmt.Errorf("incomplete ClientHello session ID length")
	}
	hello.SessionIDLen = clientHelloData[offset]
	offset += 1

	if hello.SessionIDLen > 0 {
		if offset+int(hello.SessionIDLen) > len(clientHelloData) {
			return nil, fmt.Errorf("incomplete ClientHello session ID")
		}
		hello.SessionID = make([]byte, hello.SessionIDLen)
		copy(hello.SessionID, clientHelloData[offset:offset+int(hello.SessionIDLen)])
		offset += int(hello.SessionIDLen)
	}

	// CipherSuites
	if offset+2 > len(clientHelloData) {
		return nil, fmt.Errorf("incomplete ClientHello cipher suites length")
	}
	hello.CipherSuitesLen = binary.BigEndian.Uint16(clientHelloData[offset:])
	offset += 2
	if hello.CipherSuitesLen == 0 || hello.CipherSuitesLen%2 != 0 {
		return nil, fmt.Errorf("invalid ClientHello cipher suites length: %d", hello.CipherSuitesLen)
	}

	cipherSuiteCount := int(hello.CipherSuitesLen) / 2
	hello.CipherSuites = make([]uint16, cipherSuiteCount)
	for i := 0; i < cipherSuiteCount; i++ {
		if offset+2 > len(clientHelloData) {
			return nil, fmt.Errorf("incomplete ClientHello cipher suites")
		}
		hello.CipherSuites[i] = binary.BigEndian.Uint16(clientHelloData[offset:])
		offset += 2
	}

	// CompressionMethods
	if offset+1 > len(clientHelloData) {
		return nil, fmt.Errorf("incomplete ClientHello compression methods length")
	}
	hello.CompressionMethodsLen = clientHelloData[offset]
	offset += 1

	if hello.CompressionMethodsLen > 0 {
		if offset+int(hello.CompressionMethodsLen) > len(clientHelloData) {
			return nil, fmt.Errorf("incomplete ClientHello compression methods")
		}
		hello.CompressionMethods = make([]byte, hello.CompressionMethodsLen)
		copy(hello.CompressionMethods, clientHelloData[offset:offset+int(hello.CompressionMethodsLen)])
		offset += int(hello.CompressionMethodsLen)
	}

	// Extensions
	if offset < len(clientHelloData) {
		if offset+2 > len(clientHelloData) {
			return nil, fmt.Errorf("incomplete ClientHello extensions length")
		}
		hello.ExtensionsLength = binary.BigEndian.Uint16(clientHelloData[offset:])
		offset += 2

		extensionsEnd := offset + int(hello.ExtensionsLength)
		if extensionsEnd != len(clientHelloData) {
			return nil, fmt.Errorf("invalid ClientHello extensions length")
		}
		for offset < extensionsEnd && offset+4 <= len(clientHelloData) {
			extType := binary.BigEndian.Uint16(clientHelloData[offset:])
			offset += 2
			extLength := binary.BigEndian.Uint16(clientHelloData[offset:])
			offset += 2

			if offset+int(extLength) > extensionsEnd {
				return nil, fmt.Errorf("incomplete extension data")
			}

			extData := make([]byte, extLength)
			copy(extData, clientHelloData[offset:offset+int(extLength)])
			offset += int(extLength)

			hello.Extensions = append(hello.Extensions, HelloExtension{
				Type:   extType,
				Length: extLength,
				Data:   extData,
			})
		}
		if offset != extensionsEnd {
			return nil, fmt.Errorf("incomplete extension header")
		}
	}

	record.Header = handshakeHeader
	record.Message = *hello

	return
}
