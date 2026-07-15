//go:build cgo

package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
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

func setupCapture(ctx context.Context, ifname string, configuredMTU int) (ok bool, err error, ch chan SessionInfo) {
	ch = make(chan SessionInfo)
	devList, err := pcap.FindAllDevs()

	if err != nil {
		return false, err, ch
	}

	ok = false
	for _, dev := range devList {
		if dev.Name == ifname {
			ok = true
			break
		}
	}

	if !ok && ifname != "" {
		fmt.Println("Please choose correct device name:")
		for _, dev := range devList {
			fmt.Printf("\t%s\t%s\n", dev.Name, dev.Description)
		}
		return false, nil, ch
	}

	handle, err := pcap.OpenLive(ifname, 9000, true, pcap.BlockForever)
	if err != nil {
		return
	}
	CaptureMTU = configuredMTU
	if CaptureMTU == 0 {
		CaptureMTU = 1500
		if iface, lookupErr := net.InterfaceByName(ifname); lookupErr == nil && iface.MTU > 0 {
			CaptureMTU = iface.MTU
		}
	}
	SerSentBuffer = make(chan packetInjectionRequest)
	pSource := gopacket.NewPacketSource(handle, handle.LinkType())

	pChan := pSource.Packets()

	go func() {
		defer handle.Close()
		for {
			select {
			case <-ctx.Done():
				return
			case request := <-SerSentBuffer:
				request.result <- handle.WritePacketData(request.packet.Bytes())
			case pkt, open := <-pChan:
				if !open {
					return
				}
				ethLayer := pkt.Layer(layers.LayerTypeEthernet)
				ip4Layer := pkt.Layer(layers.LayerTypeIPv4)
				tcpLayer := pkt.Layer(layers.LayerTypeTCP)
				if ethLayer == nil || ip4Layer == nil || tcpLayer == nil {
					continue
				}

				eth, _ := ethLayer.(*layers.Ethernet)
				ip4, _ := ip4Layer.(*layers.IPv4)
				tcp, _ := tcpLayer.(*layers.TCP)

				if tcp.SYN && tcp.ACK {
					si := SessionInfo{
						SrcMAC:  eth.DstMAC,
						DstMAC:  eth.SrcMAC,
						SrcIP:   ip4.DstIP,
						DstIP:   ip4.SrcIP,
						SrcPort: uint16(tcp.DstPort),
						DstPort: uint16(tcp.SrcPort),
						ISN:     uint32(tcp.Ack),
						Ack:     uint32(tcp.Seq) + 1,
						SeenAt:  time.Now(),
					}
					for _, option := range tcp.Options {
						if option.OptionType == layers.TCPOptionKindTimestamps && len(option.OptionData) == 8 {
							si.HasTimestamp = true
							si.ServerTS = binary.BigEndian.Uint32(option.OptionData[0:4])
							si.ClientTS = binary.BigEndian.Uint32(option.OptionData[4:8])
							break
						}
					}
					ch <- si
				} else if tcp.ACK && len(tcp.Payload) == 0 {
					si := SessionInfo{
						SrcIP:      ip4.SrcIP,
						DstIP:      ip4.DstIP,
						SrcPort:    uint16(tcp.SrcPort),
						DstPort:    uint16(tcp.DstPort),
						SeenAt:     time.Now(),
						Window:     tcp.Window,
						UpdateOnly: true,
					}
					for _, option := range tcp.Options {
						if option.OptionType == layers.TCPOptionKindTimestamps && len(option.OptionData) == 8 {
							si.HasTimestamp = true
							si.ClientTS = binary.BigEndian.Uint32(option.OptionData[0:4])
							si.ServerTS = binary.BigEndian.Uint32(option.OptionData[4:8])
							break
						}
					}
					ch <- si
				}
				//fmt.Printf(pkt.String())

			}
		}
	}()
	return
}

func TrackSessions(ch chan SessionInfo) {
	for s := range ch {
		if s.UpdateOnly {
			RSB.Update(s)
		} else {
			RSB.Append(s)
		}
	}
}

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

	// Rotate
	if len(r.Entries) > 500 {
		copy(r.Entries, r.Entries[len(r.Entries)-500:])
		r.Entries = r.Entries[:500]
	}

	fmt.Printf("%v:%v => %v:%v (%v)\n", si.SrcIP, si.SrcPort, si.DstIP, si.DstPort, si.ISN)
	return
}

func (r *RingSessionBuffer) Lookup(si SessionInfo) (ok bool, session SessionInfo) {
	fmt.Printf("SEARCH for session %v:%v => %v:%v (%v)\n", si.SrcIP, si.SrcPort, si.DstIP, si.DstPort, si.ISN)
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
	return
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

func PrepareFakePacket(si SessionInfo, ttl uint8, data []byte) (err error, msg gopacket.SerializeBuffer) {
	// Generate fake packet
	el := &layers.Ethernet{
		SrcMAC:       si.SrcMAC,
		DstMAC:       si.DstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}
	il := &layers.IPv4{
		Version:  4,
		TTL:      ttl,
		SrcIP:    si.SrcIP,
		DstIP:    si.DstIP,
		Protocol: layers.IPProtocolTCP,
	}
	tl := &layers.TCP{
		SrcPort: layers.TCPPort(si.SrcPort),
		DstPort: layers.TCPPort(si.DstPort),
		Seq:     si.ISN,
		Ack:     si.Ack,
		Window:  si.Window,
		ACK:     true,
		PSH:     true,
	}
	if tl.Window == 0 {
		tl.Window = 8192
	}
	if si.HasTimestamp {
		timestamp := make([]byte, 8)
		elapsed := uint32(time.Since(si.SeenAt) / time.Millisecond)
		binary.BigEndian.PutUint32(timestamp[0:4], si.ClientTS+elapsed)
		binary.BigEndian.PutUint32(timestamp[4:8], si.ServerTS)
		tl.Options = []layers.TCPOption{
			{OptionType: layers.TCPOptionKindNop},
			{OptionType: layers.TCPOptionKindNop},
			{OptionType: layers.TCPOptionKindTimestamps, OptionLength: 10, OptionData: timestamp},
		}
	}
	_ = tl.SetNetworkLayerForChecksum(il)
	buffer := gopacket.NewSerializeBuffer()

	options := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	err = gopacket.SerializeLayers(buffer, options,
		el,
		il,
		tl,
		gopacket.Payload(data),
	)
	if err == nil && len(buffer.Bytes()) > CaptureMTU+14 {
		return fmt.Errorf("fake Ethernet frame length %d exceeds MTU frame limit %d", len(buffer.Bytes()), CaptureMTU+14), nil
	}
	return err, buffer
}

func injectPacket(packet gopacket.SerializeBuffer) error {
	if SerSentBuffer == nil {
		return fmt.Errorf("packet capture is not initialized")
	}
	result := make(chan error, 1)
	request := packetInjectionRequest{packet: packet, result: result}
	select {
	case SerSentBuffer <- request:
	case <-time.After(time.Second):
		return fmt.Errorf("packet injection queue timeout")
	}
	select {
	case err := <-result:
		return err
	case <-time.After(time.Second):
		return fmt.Errorf("packet injection result timeout")
	}
}
