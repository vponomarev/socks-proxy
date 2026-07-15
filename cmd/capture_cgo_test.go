//go:build cgo

package main

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/google/gopacket"
)

func TestPrepareFakePacketEnforcesMTU(t *testing.T) {
	previousMTU := CaptureMTU
	CaptureMTU = 1500
	t.Cleanup(func() { CaptureMTU = previousMTU })
	session := SessionInfo{
		SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1},
		DstMAC: net.HardwareAddr{2, 0, 0, 0, 0, 2},
		SrcIP:  net.IPv4(192, 0, 2, 1), DstIP: net.IPv4(198, 51, 100, 1),
		SrcPort: 40000, DstPort: 443, ISN: 100, Ack: 200,
		SeenAt: time.Now(), HasTimestamp: true, ClientTS: 1000, ServerTS: 2000,
	}
	if err, packet := PrepareFakePacket(session, 7, make([]byte, 1448)); err != nil || len(packet.Bytes()) != 1514 {
		t.Fatalf("maximum packet: err=%v bytes=%d", err, len(packet.Bytes()))
	}
	if err, _ := PrepareFakePacket(session, 7, make([]byte, 1449)); err == nil {
		t.Fatal("PrepareFakePacket accepted payload over MTU")
	}
}

func TestInjectPacketReturnsWriterResult(t *testing.T) {
	previous := SerSentBuffer
	SerSentBuffer = make(chan packetInjectionRequest)
	t.Cleanup(func() { SerSentBuffer = previous })
	want := errors.New("write failed")
	go func() {
		request := <-SerSentBuffer
		request.result <- want
	}()
	if got := injectPacket(gopacket.NewSerializeBuffer()); !errors.Is(got, want) {
		t.Fatalf("injectPacket() = %v", got)
	}
}
