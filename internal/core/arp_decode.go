package core

import (
	"net"
	"net/netip"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func DecodeARPEvent(p gopacket.Packet) (ARPEvent, bool) {
	ethL := p.Layer(layers.LayerTypeEthernet)
	arpL := p.Layer(layers.LayerTypeARP)
	if ethL == nil || arpL == nil {
		return ARPEvent{}, false
	}

	eth := ethL.(*layers.Ethernet)
	arp := arpL.(*layers.ARP)

	// Focus on ARP over Ethernet for IPv4.
	if arp.AddrType != layers.LinkTypeEthernet || arp.Protocol != layers.EthernetTypeIPv4 {
		return ARPEvent{}, false
	}
	if len(arp.SourceHwAddress) != 6 || len(arp.DstHwAddress) != 6 ||
		len(arp.SourceProtAddress) != 4 || len(arp.DstProtAddress) != 4 {
		return ARPEvent{}, false
	}

	var ts time.Time
	if md := p.Metadata(); md != nil {
		ts = md.Timestamp
	}

	e := ARPEvent{
		Timestamp: ts,

		SrcMAC: net.HardwareAddr(append([]byte(nil), eth.SrcMAC...)),
		DstMAC: net.HardwareAddr(append([]byte(nil), eth.DstMAC...)),

		Op: arp.Operation,

		SenderMAC: net.HardwareAddr(append([]byte(nil), arp.SourceHwAddress...)),
		TargetMAC: net.HardwareAddr(append([]byte(nil), arp.DstHwAddress...)),
	}

	if ip, ok := netip.AddrFromSlice(arp.SourceProtAddress); ok {
		e.SenderIP = ip
	}
	if ip, ok := netip.AddrFromSlice(arp.DstProtAddress); ok {
		e.TargetIP = ip
	}

	return e, true
}
