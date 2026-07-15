package main

import (
	"bytes"
	"testing"

	"github.com/vponomarev/socks-proxy/internal/libtls"
)

func TestBuildFakeClientHelloPreservesSmallClientFingerprint(t *testing.T) {
	record := libtls.NewTLSRecord(&libtls.ClientHello{
		Version:            0x0303,
		CipherSuites:       []uint16{0x1301, 0x1302},
		CompressionMethods: []byte{0},
		Extensions: []libtls.HelloExtension{
			{Type: 43, Data: []byte{2, 3, 4}},
			{Type: 1234, Data: []byte("fingerprint-marker")},
		},
	})
	record.Message.ReplaceSNI("blocked.example")
	data, source, err := buildFakeClientHello(record, "allowed.example", 1448)
	if err != nil {
		t.Fatal(err)
	}
	if source != "client" {
		t.Fatalf("source = %q", source)
	}
	decoded, err := libtls.DecodeTLS(data)
	if err != nil {
		t.Fatal(err)
	}
	if _, sni := decoded.Message.FindSNI(); sni != "allowed.example" {
		t.Fatalf("SNI = %q", sni)
	}
	ok, _, marker := decoded.Message.FindExtension(1234)
	if !ok || !bytes.Equal(marker, []byte("fingerprint-marker")) {
		t.Fatal("client fingerprint extension was not preserved")
	}
}

func TestBuildFakeClientHelloGeneratesFallbackForLargeClient(t *testing.T) {
	record := libtls.NewTLSRecord(&libtls.ClientHello{
		Version:            0x0303,
		CipherSuites:       []uint16{0x1301},
		CompressionMethods: []byte{0},
		Extensions: []libtls.HelloExtension{
			{Type: 1234, Data: bytes.Repeat([]byte{1}, 2000)},
		},
	})
	data, source, err := buildFakeClientHello(record, "allowed.example", 1448)
	if err != nil {
		t.Fatal(err)
	}
	if source != "generated" || len(data) > 1448 {
		t.Fatalf("source=%q bytes=%d", source, len(data))
	}
}
