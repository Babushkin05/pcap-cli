package router_mac

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/Babushkin05/pcap-cli/internal/core"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type ResolveOptions struct {
	Iface       string
	SnapLen     int
	Promisc     bool
	ReadTimeout time.Duration // to check ctx.Done()

	WaitPerTry time.Duration
	Retries    int
}

func ResolveMACByARP(ctx context.Context, opts ResolveOptions, myIP netip.Addr, myMAC net.HardwareAddr, targetIP netip.Addr) (net.HardwareAddr, error) {
	if !myIP.IsValid() || !myIP.Is4() {
		return nil, fmt.Errorf("resolve: myIP must be valid IPv4")
	}
	if len(myMAC) != 6 {
		return nil, fmt.Errorf("resolve: myMAC must be 6 bytes")
	}
	if !targetIP.IsValid() || !targetIP.Is4() {
		return nil, fmt.Errorf("resolve: targetIP must be valid IPv4")
	}
	if opts.Iface == "" {
		return nil, fmt.Errorf("resolve: iface is required")
	}
	if opts.ReadTimeout == 0 {
		opts.ReadTimeout = 200 * time.Millisecond
	}
	if opts.WaitPerTry == 0 {
		opts.WaitPerTry = 1500 * time.Millisecond
	}
	if opts.Retries <= 0 {
		opts.Retries = 2
	}

	h, err := core.OpenPcapHandle(core.CaptureOptions{
		Iface:   opts.Iface,
		SnapLen: opts.SnapLen,
		Promisc: opts.Promisc,
		Timeout: opts.ReadTimeout,
	})
	if err != nil {
		return nil, err
	}
	defer h.Close()

	// Listen only to ARP to avoid CPU waste.
	// Reply we will still match in code by IP.
	if err := core.SetBPF(h, "arp"); err != nil {
		return nil, err
	}

	reqBytes, err := buildARPRequestFrame(myMAC, myIP, targetIP)
	if err != nil {
		return nil, err
	}

	for attempt := 1; attempt <= opts.Retries; attempt++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		// Send ARP request (Ethernet broadcast).
		if err := h.WritePacketData(reqBytes); err != nil {
			return nil, fmt.Errorf("resolve: send arp request: %w", err)
		}

		deadline := time.Now().Add(opts.WaitPerTry)

		for time.Now().Before(deadline) {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			default:
			}

			data, ci, err := h.ReadPacketData()
			if err != nil {
				if err == pcap.NextErrorTimeoutExpired {
					continue
				}
				return nil, fmt.Errorf("resolve: read packet: %w", err)
			}

			p := gopacket.NewPacket(data, h.LinkType(), gopacket.NoCopy)
			e, ok := core.DecodeARPEvent(p)
			if !ok {
				continue
			}
			if e.Timestamp.IsZero() {
				e.Timestamp = ci.Timestamp
			}

			// Need reply from targetIP addressed to us (preferably).
			if e.Op != core.ARPOpReply {
				continue
			}
			if e.SenderIP != targetIP {
				continue
			}
			// Usually reply goes "to myIP", but sometimes we can catch it loosely.
			if e.TargetIP.IsValid() && e.TargetIP != myIP {
				continue
			}
			if len(e.SenderMAC) != 6 {
				continue
			}

			return e.SenderMAC, nil
		}
	}

	return nil, errors.New("resolve: no arp reply received")
}

func buildARPRequestFrame(myMAC net.HardwareAddr, myIP netip.Addr, targetIP netip.Addr) ([]byte, error) {
	if len(myMAC) != 6 {
		return nil, fmt.Errorf("build arp: myMAC must be 6 bytes")
	}
	myIP4 := myIP.As4()
	targetIP4 := targetIP.As4()

	eth := layers.Ethernet{
		SrcMAC:       myMAC,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}

	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         core.ARPOpRequest,
		SourceHwAddress:   []byte(myMAC),
		SourceProtAddress: myIP4[:],
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    targetIP4[:],
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: false, // not needed for ARP
	}

	if err := gopacket.SerializeLayers(buf, opts, &eth, &arp); err != nil {
		return nil, fmt.Errorf("build arp: serialize: %w", err)
	}
	out := buf.Bytes()
	if len(out) == 0 {
		return nil, errors.New("build arp: empty frame")
	}
	return out, nil
}
