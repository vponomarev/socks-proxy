//go:build !cgo

package main

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/google/gopacket"
)

type SessionInfo struct {
	SrcMAC  net.HardwareAddr
	DstMAC  net.HardwareAddr
	SrcIP   net.IP
	DstIP   net.IP
	SrcPort uint16
	DstPort uint16
	ISN     uint32
	Ack     uint32
}

type RingSessionBuffer struct {
	Entries []SessionInfo
	sync.RWMutex
}

func (r *RingSessionBuffer) Append(si SessionInfo) {
	r.Lock()
	defer r.Unlock()
	r.Entries = append(r.Entries, si)
}

func (r *RingSessionBuffer) Lookup(si SessionInfo) (bool, SessionInfo) {
	r.RLock()
	defer r.RUnlock()
	for _, entry := range r.Entries {
		if entry.SrcIP.Equal(si.SrcIP) && entry.DstIP.Equal(si.DstIP) && entry.SrcPort == si.SrcPort && entry.DstPort == si.DstPort {
			return true, entry
		}
	}
	return false, SessionInfo{}
}

func setupCapture(context.Context, string) (bool, error, chan SessionInfo) {
	return false, fmt.Errorf("packet capture is unavailable in a CGO-disabled build"), make(chan SessionInfo)
}

func TrackSessions(ch chan SessionInfo) {
	for session := range ch {
		RSB.Append(session)
	}
}

func PrepareFakePacket(SessionInfo, uint8, []byte) (error, gopacket.SerializeBuffer) {
	return fmt.Errorf("packet injection is unavailable in a CGO-disabled build"), nil
}
