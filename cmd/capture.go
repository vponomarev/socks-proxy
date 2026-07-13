//go:build cgo

package main

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
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

func setupCapture(ctx context.Context, ifname string) (ok bool, err error, ch chan SessionInfo) {
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
	SerSentBuffer = make(chan gopacket.SerializeBuffer)
	pSource := gopacket.NewPacketSource(handle, handle.LinkType())

	pChan := pSource.Packets()

	go func() {
		for {
			select {
			case sb := <-SerSentBuffer:
				err = handle.WritePacketData(sb.Bytes())
				if err != nil {
					fmt.Printf("==== Error injecting fake packet: %v\n", err)
				}
				continue
			case pkt := <-pChan:
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
	for {
		select {
		case s := <-ch:
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
	for _, entry := range r.Entries {
		if entry.SrcIP.Equal(si.SrcIP) && entry.DstIP.Equal(si.DstIP) && entry.SrcPort == si.SrcPort && entry.DstPort == si.DstPort {
			return true, entry
		}
	}
	return
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
		Window:  8192,
		ACK:     true,
		PSH:     true,
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
	return err, buffer
}
