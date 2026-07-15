package libtls

import (
	"bytes"
	"testing"
)

func TestEncodeCompactKeepsValidSNIAndX25519(t *testing.T) {
	keyShares := &KeyShare{Extensions: []KeyShareExtension{
		{Group: TLS_KEY_SHARE_X25519MLKEM768, KeyExchange: bytes.Repeat([]byte{0xa5}, 1300)},
		{Group: TLS_KEY_SHARE_x25519, KeyExchange: bytes.Repeat([]byte{0x5a}, 32)},
	}}
	_, keyShareExtension := keyShares.Encode()
	record := NewTLSRecord(&ClientHello{
		Version:            0x0303,
		CipherSuites:       []uint16{0x1301, 0x1302},
		CompressionMethods: []byte{0},
		Extensions: []HelloExtension{
			{Type: 43, Data: []byte{2, 3, 4}},
			{Type: 10, Data: []byte{0, 2, 0, TLS_KEY_SHARE_x25519}},
			{Type: 13, Data: []byte{0, 2, 4, 3}},
			keyShareExtension,
			{Type: TLS_EXTENSION_PADDING, Data: bytes.Repeat([]byte{0}, 100)},
			{Type: TLS_EXTENSION_ECH, Data: bytes.Repeat([]byte{1}, 100)},
		},
	})
	record.Message.ReplaceSNI("blocked.example")
	original, err := record.EncodeTLS()
	if err != nil {
		t.Fatal(err)
	}
	if len(original) <= 1460 {
		t.Fatalf("test ClientHello is unexpectedly small: %d", len(original))
	}

	compactRecord := record.Clone()
	compactRecord.Message.ReplaceSNI("allowed.example")
	compact, err := compactRecord.EncodeCompact(1460)
	if err != nil {
		t.Fatal(err)
	}
	if len(compact) > 1460 {
		t.Fatalf("compact ClientHello = %d bytes", len(compact))
	}
	decoded, err := DecodeTLS(compact)
	if err != nil {
		t.Fatalf("compact ClientHello is invalid: %v", err)
	}
	if ok, sni := decoded.Message.FindSNI(); !ok || sni != "allowed.example" {
		t.Fatalf("FindSNI() = %t, %q", ok, sni)
	}
	ok, id, _ := decoded.Message.FindExtension(TLS_EXTENSION_KEY_SHARE)
	if !ok {
		t.Fatal("key_share was removed")
	}
	compactShares, err := decoded.Message.Extensions[id].DecodeKeyShare()
	if err != nil {
		t.Fatal(err)
	}
	if len(compactShares.Extensions) != 1 || compactShares.Extensions[0].Group != TLS_KEY_SHARE_x25519 {
		t.Fatalf("unexpected compact key shares: %#v", compactShares.Extensions)
	}
	if _, sni := record.Message.FindSNI(); sni != "blocked.example" {
		t.Fatalf("Clone modified original SNI: %q", sni)
	}
}

func TestEncodeCompactRejectsPayloadThatStillExceedsLimit(t *testing.T) {
	record := NewTLSRecord(&ClientHello{
		CipherSuites:       []uint16{0x1301},
		CompressionMethods: []byte{0},
		Extensions: []HelloExtension{
			{Type: 16, Data: bytes.Repeat([]byte{1}, 2000)},
		},
	})
	if _, err := record.EncodeCompact(1460); err == nil {
		t.Fatal("EncodeCompact accepted an oversized ClientHello")
	}
}

func TestFindSNIRejectsMalformedExtension(t *testing.T) {
	hello := ClientHello{Extensions: []HelloExtension{{Type: 0, Data: []byte{0, 1, 0}}}}
	if ok, _ := hello.FindSNI(); ok {
		t.Fatal("FindSNI accepted malformed SNI")
	}
}

func TestRemoveMiddleExtension(t *testing.T) {
	hello := ClientHello{Extensions: []HelloExtension{{Type: 1}, {Type: 2}, {Type: 3}}}
	if !hello.RemoveExtension(1) {
		t.Fatal("RemoveExtension failed")
	}
	if len(hello.Extensions) != 2 || hello.Extensions[0].Type != 1 || hello.Extensions[1].Type != 3 {
		t.Fatalf("unexpected extensions: %#v", hello.Extensions)
	}
}
