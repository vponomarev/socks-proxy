package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/vponomarev/socks-proxy/internal/config"
	"github.com/vponomarev/socks-proxy/internal/libtls"
)

const maxTLSRecordSize = 5 + 65535

// byeWriter buffers only the first TLS record. Once the ClientHello is
// complete it is sent in two writes split inside the SNI. All later traffic
// passes through unchanged.
type byeWriter struct {
	conn   net.Conn
	config config.Bye
	buffer []byte
	done   bool
}

func newByeWriter(conn net.Conn, cfg config.Bye) *byeWriter {
	return &byeWriter{conn: conn, config: cfg, buffer: make([]byte, 0, 4096)}
}

func (w *byeWriter) Write(data []byte) error {
	if w.done {
		return writeConn(w.conn, data)
	}
	w.buffer = append(w.buffer, data...)
	if len(w.buffer) < 5 {
		return nil
	}
	if w.buffer[0] != 0x16 {
		return w.flushUnchanged()
	}
	recordSize := 5 + int(binary.BigEndian.Uint16(w.buffer[3:5]))
	if recordSize > maxTLSRecordSize {
		return w.flushUnchanged()
	}
	if len(w.buffer) < recordSize {
		return nil
	}
	w.done = true
	data = w.buffer
	w.buffer = nil
	if _, _, err := libtls.ClientHelloSNIRange(data); err != nil {
		// A static bye policy must remain transparent for TLS without SNI.
		return writeConn(w.conn, data)
	}
	if err := sendByeClientHello(w.conn, data, w.config); err != nil {
		return err
	}
	return nil
}

func (w *byeWriter) flushUnchanged() error {
	w.done = true
	data := w.buffer
	w.buffer = nil
	return writeConn(w.conn, data)
}

func sendByeClientHello(conn net.Conn, data []byte, cfg config.Bye) error {
	start, end, err := libtls.ClientHelloSNIRange(data)
	if err != nil {
		return fmt.Errorf("locate SNI split point: %w", err)
	}
	split := start + cfg.Offset()
	if split >= end {
		split = start + (end-start)/2
	}
	if split <= start || split >= end {
		return fmt.Errorf("SNI is too short to split")
	}

	if tcp, ok := conn.(*net.TCPConn); ok {
		if err := tcp.SetNoDelay(true); err != nil {
			return fmt.Errorf("enable TCP_NODELAY: %w", err)
		}
	}
	first, second, err := byeChunks(data, split, cfg.SplitMode())
	if err != nil {
		return err
	}
	if err := writeConn(conn, first); err != nil {
		return err
	}
	if delay := cfg.SplitDelay(); delay > 0 {
		time.Sleep(delay)
	}
	return writeConn(conn, second)
}

func byeChunks(data []byte, split int, mode string) ([]byte, []byte, error) {
	if split <= 5 || split >= len(data) {
		return nil, nil, fmt.Errorf("invalid ClientHello split point %d", split)
	}
	if mode == "tcp-split" {
		return data[:split], data[split:], nil
	}
	if mode != "tlsrec" {
		return nil, nil, fmt.Errorf("unsupported bye mode %q", mode)
	}
	recordEnd := 5 + int(binary.BigEndian.Uint16(data[3:5]))
	if split >= recordEnd || recordEnd > len(data) {
		return nil, nil, fmt.Errorf("invalid TLS record split point %d", split)
	}
	first := make([]byte, 5+split-5)
	copy(first[:5], data[:5])
	binary.BigEndian.PutUint16(first[3:5], uint16(split-5))
	copy(first[5:], data[5:split])

	secondBody := recordEnd - split
	second := make([]byte, 5+secondBody+len(data)-recordEnd)
	copy(second[:3], data[:3])
	binary.BigEndian.PutUint16(second[3:5], uint16(secondBody))
	copy(second[5:5+secondBody], data[split:recordEnd])
	copy(second[5+secondBody:], data[recordEnd:])
	return first, second, nil
}
