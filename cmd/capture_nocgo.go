//go:build !cgo

package main

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
)

type SessionInfo struct {
	SrcMAC       net.HardwareAddr
	DstMAC       net.HardwareAddr
	SrcIP        net.IP
	DstIP        net.IP
	SrcPort      uint16
	DstPort      uint16
	ISN          uint32
	Ack          uint32
	SeenAt       time.Time
	HasTimestamp bool
	ClientTS     uint32
	ServerTS     uint32
	Window       uint16
	UpdateOnly   bool
}

const sessionMaxAge = time.Minute

type RingSessionBuffer struct {
	Entries []SessionInfo
	sync.RWMutex
}

func (r *RingSessionBuffer) Append(si SessionInfo) {
	r.Lock()
	defer r.Unlock()
	if si.SeenAt.IsZero() {
		si.SeenAt = time.Now()
	}
	r.Entries = append(r.Entries, si)
}

func (r *RingSessionBuffer) Lookup(si SessionInfo) (bool, SessionInfo) {
	r.RLock()
	defer r.RUnlock()
	for i := len(r.Entries) - 1; i >= 0; i-- {
		entry := r.Entries[i]
		if time.Since(entry.SeenAt) > sessionMaxAge {
			continue
		}
		if entry.SrcIP.Equal(si.SrcIP) && entry.DstIP.Equal(si.DstIP) && entry.SrcPort == si.SrcPort && entry.DstPort == si.DstPort {
			return true, entry
		}
	}
	return false, SessionInfo{}
}

func (r *RingSessionBuffer) Update(si SessionInfo) bool {
	r.Lock()
	defer r.Unlock()
	for i := len(r.Entries) - 1; i >= 0; i-- {
		entry := &r.Entries[i]
		if entry.SrcIP.Equal(si.SrcIP) && entry.DstIP.Equal(si.DstIP) && entry.SrcPort == si.SrcPort && entry.DstPort == si.DstPort {
			entry.SeenAt = si.SeenAt
			entry.Window = si.Window
			if si.HasTimestamp {
				entry.HasTimestamp = true
				entry.ClientTS = si.ClientTS
				entry.ServerTS = si.ServerTS
			}
			return true
		}
	}
	return false
}

func setupCapture(context.Context, string, int) (bool, error, chan SessionInfo) {
	return false, fmt.Errorf("packet capture is unavailable in a CGO-disabled build"), make(chan SessionInfo)
}

func TrackSessions(ch chan SessionInfo) {
	for session := range ch {
		if session.UpdateOnly {
			RSB.Update(session)
		} else {
			RSB.Append(session)
		}
	}
}

func PrepareFakePacket(SessionInfo, uint8, []byte) (error, gopacket.SerializeBuffer) {
	return fmt.Errorf("packet injection is unavailable in a CGO-disabled build"), nil
}

func injectPacket(gopacket.SerializeBuffer) error {
	return fmt.Errorf("packet injection is unavailable in a CGO-disabled build")
}
