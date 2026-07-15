package main

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"

	"github.com/vponomarev/socks-proxy/internal/config"
	"github.com/vponomarev/socks-proxy/internal/libtls"
)

func TestByeChunksTCPSplitPreservesClientHello(t *testing.T) {
	hello := testClientHello(t)
	start, _, err := libtls.ClientHelloSNIRange(hello)
	if err != nil {
		t.Fatal(err)
	}
	first, second, err := byeChunks(hello, start+3, "tcp-split")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(append(bytes.Clone(first), second...), hello) {
		t.Fatal("TCP split changed ClientHello bytes")
	}
}

func TestByeChunksTLSRecordsRemainDecodable(t *testing.T) {
	hello := testClientHello(t)
	start, _, err := libtls.ClientHelloSNIRange(hello)
	if err != nil {
		t.Fatal(err)
	}
	first, second, err := byeChunks(hello, start+3, "tlsrec")
	if err != nil {
		t.Fatal(err)
	}
	if int(binary.BigEndian.Uint16(first[3:5])) != len(first)-5 {
		t.Fatal("first TLS record length is invalid")
	}
	secondRecordLength := int(binary.BigEndian.Uint16(second[3:5]))
	reassembled := append(bytes.Clone(first[5:]), second[5:5+secondRecordLength]...)
	if !bytes.Equal(reassembled, hello[5:]) {
		t.Fatal("TLS record split changed handshake bytes")
	}
}

func TestByeWriterBuffersFragmentedClientHello(t *testing.T) {
	hello := testClientHello(t)
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	writer := newByeWriter(client, config.Bye{Mode: "tcp-split", Delay: "0s"})
	done := make(chan error, 1)
	go func() {
		got := make([]byte, len(hello))
		_, err := io.ReadFull(server, got)
		if err == nil && !bytes.Equal(got, hello) {
			err = io.ErrUnexpectedEOF
		}
		done <- err
	}()
	if err := writer.Write(hello[:10]); err != nil {
		t.Fatal(err)
	}
	if err := writer.Write(hello[10:]); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func testClientHello(t *testing.T) []byte {
	t.Helper()
	hello, err := libtls.GenerateClientHello("split.example", 1400)
	if err != nil {
		t.Fatal(err)
	}
	return hello
}
