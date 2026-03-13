package libtls

import (
	"encoding/binary"
	"fmt"
)

func (t *TLSRecord) EncodeTLS() (data []byte, err error) {
	// Валидация основных полей
	if t.ContentType != 0x16 {
		return nil, fmt.Errorf("invalid content type for handshake: 0x%02x", t.ContentType)
	}

	// 1. Кодируем ClientHello
	clientHelloData, err := t.encodeClientHello()
	if err != nil {
		return nil, fmt.Errorf("encoding client hello: %w", err)
	}

	// 2. Кодируем HandshakeHeader
	handshakeHeaderData := t.encodeHandshakeHeader(uint32(len(clientHelloData)))

	// 3. Собираем полные handshake данные
	handshakeData := append(handshakeHeaderData, clientHelloData...)

	// 4. Обновляем Length в TLSRecord
	t.Length = uint16(len(handshakeData))

	// 5. Кодируем TLS Record Header
	recordHeader := t.encodeTLSRecordHeader()

	// 6. Собираем финальные данные
	data = append(recordHeader, handshakeData...)

	return data, nil
}

func (t *TLSRecord) encodeTLSRecordHeader() []byte {
	data := make([]byte, 5)
	data[0] = t.ContentType
	binary.BigEndian.PutUint16(data[1:3], t.Version)
	binary.BigEndian.PutUint16(data[3:5], t.Length)
	return data
}

func (t *TLSRecord) encodeHandshakeHeader(messageLength uint32) []byte {
	data := make([]byte, 4)
	data[0] = t.Header.MsgType

	// Кодируем 3-байтовую длину (big endian)
	data[1] = byte((messageLength >> 16) & 0xFF)
	data[2] = byte((messageLength >> 8) & 0xFF)
	data[3] = byte(messageLength & 0xFF)

	return data
}

func (t *TLSRecord) encodeClientHello() ([]byte, error) {
	var data []byte

	// Version (2 bytes)
	versionBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(versionBytes, t.Message.Version)
	data = append(data, versionBytes...)

	// Random (32 bytes)
	data = append(data, t.Message.Random[:]...)

	// SessionID
	if t.Message.SessionIDLen > 32 { // Максимальная длина по спецификации
		return nil, fmt.Errorf("session ID too long: %d", t.Message.SessionIDLen)
	}
	data = append(data, t.Message.SessionIDLen)
	if t.Message.SessionIDLen > 0 {
		if len(t.Message.SessionID) != int(t.Message.SessionIDLen) {
			return nil, fmt.Errorf("session ID length mismatch: expected %d, got %d",
				t.Message.SessionIDLen, len(t.Message.SessionID))
		}
		data = append(data, t.Message.SessionID...)
	}

	// CipherSuites
	if len(t.Message.CipherSuites)*2 > 65535 {
		return nil, fmt.Errorf("cipher suites too long")
	}
	cipherSuitesLen := uint16(len(t.Message.CipherSuites) * 2)
	lenBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBytes, cipherSuitesLen)
	data = append(data, lenBytes...)

	for _, suite := range t.Message.CipherSuites {
		suiteBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(suiteBytes, suite)
		data = append(data, suiteBytes...)
	}

	// CompressionMethods
	if len(t.Message.CompressionMethods) > 255 {
		return nil, fmt.Errorf("compression methods too long")
	}
	data = append(data, byte(len(t.Message.CompressionMethods)))
	if len(t.Message.CompressionMethods) > 0 {
		data = append(data, t.Message.CompressionMethods...)
	}

	// Extensions
	extensionsData, err := t.encodeExtensions()
	if err != nil {
		return nil, fmt.Errorf("encoding extensions: %w", err)
	}

	if len(extensionsData) > 0 {
		if len(extensionsData) > 65535 {
			return nil, fmt.Errorf("extensions too long")
		}
		extLenBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(extLenBytes, uint16(len(extensionsData)))
		data = append(data, extLenBytes...)
		data = append(data, extensionsData...)
	} else {
		// Если нет расширений, добавляем нулевую длину
		data = append(data, 0x00, 0x00)
	}

	return data, nil
}

func (t *TLSRecord) encodeExtensions() ([]byte, error) {
	var data []byte

	for _, ext := range t.Message.Extensions {
		// Проверяем длину данных расширения
		if len(ext.Data) > 65535 {
			return nil, fmt.Errorf("extension data too long: type=0x%04x, len=%d",
				ext.Type, len(ext.Data))
		}

		// Type (2 bytes)
		typeBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(typeBytes, ext.Type)
		data = append(data, typeBytes...)

		// Length (2 bytes)
		lengthBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(lengthBytes, uint16(len(ext.Data)))
		data = append(data, lengthBytes...)

		// Data
		data = append(data, ext.Data...)
	}

	return data, nil
}

// Вспомогательные методы для удобства
func (t *TLSRecord) UpdateLengths() {
	// Обновляем длины в структуре ClientHello на основе фактических данных
	t.Message.SessionIDLen = uint8(len(t.Message.SessionID))
	t.Message.CipherSuitesLen = uint16(len(t.Message.CipherSuites) * 2)
	t.Message.CompressionMethodsLen = uint8(len(t.Message.CompressionMethods))
	t.Message.ExtensionsLength = uint16(t.calculateExtensionsLength())
}

func (t *TLSRecord) calculateExtensionsLength() int {
	total := 0
	for _, ext := range t.Message.Extensions {
		total += 4 + len(ext.Data) // type(2) + length(2) + data
	}
	return total
}

// Конструктор для удобного создания TLSRecord
func NewTLSRecord(clientHello *ClientHello) *TLSRecord {
	return &TLSRecord{
		ContentType: 0x16,   // Handshake
		Version:     0x0303, // TLS 1.2
		Header: HandshakeHeader{
			MsgType: 0x01, // ClientHello
		},
		Message: *clientHello,
	}
}
