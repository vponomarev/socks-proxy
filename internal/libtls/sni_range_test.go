package libtls

import (
	"bytes"
	"testing"
)

func TestClientHelloSNIRange(t *testing.T) {
	hello, err := GenerateClientHello("split.example", 1400)
	if err != nil {
		t.Fatal(err)
	}
	start, end, err := ClientHelloSNIRange(hello)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(hello[start:end]); got != "split.example" {
		t.Fatalf("SNI range = %q", got)
	}
	if _, _, err := ClientHelloSNIRange(hello[:len(hello)-1]); err == nil {
		t.Fatal("accepted incomplete ClientHello")
	}
	broken := bytes.Clone(hello)
	broken[0] = 0x17
	if _, _, err := ClientHelloSNIRange(broken); err == nil {
		t.Fatal("accepted non-handshake record")
	}
}
