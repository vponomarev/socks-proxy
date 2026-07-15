package libtls

import "testing"

func TestGenerateClientHello(t *testing.T) {
	data, err := GenerateClientHello("allowed.example", 1448)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) >= 1000 {
		t.Fatalf("generated ClientHello is unexpectedly large: %d", len(data))
	}
	record, err := DecodeTLS(data)
	if err != nil {
		t.Fatal(err)
	}
	if ok, sni := record.Message.FindSNI(); !ok || sni != "allowed.example" {
		t.Fatalf("FindSNI() = %t, %q", ok, sni)
	}
	ok, id, _ := record.Message.FindExtension(TLS_EXTENSION_KEY_SHARE)
	if !ok {
		t.Fatal("generated ClientHello has no key_share")
	}
	shares, err := record.Message.Extensions[id].DecodeKeyShare()
	if err != nil {
		t.Fatal(err)
	}
	if len(shares.Extensions) != 1 || shares.Extensions[0].Group != TLS_KEY_SHARE_x25519 {
		t.Fatalf("unexpected key shares: %#v", shares.Extensions)
	}
}

func TestGenerateClientHelloRejectsSmallLimit(t *testing.T) {
	if _, err := GenerateClientHello("allowed.example", 10); err == nil {
		t.Fatal("GenerateClientHello accepted an impossible size limit")
	}
}
