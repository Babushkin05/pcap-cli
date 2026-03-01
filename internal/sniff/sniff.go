package sniff

import (
	"context"
	"fmt"
	"time"

	"github.com/Babushkin05/pcap-cli/internal/core"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

type SniffOptions struct {
	Iface   string
	SnapLen int
	Promisc bool

	// ReadTimeout нужен, чтобы цикл мог регулярно проверять ctx.Done().
	// Если поставить BlockForever, остановка по ctx может “залипнуть” до следующего пакета.
	ReadTimeout time.Duration

	// BPF по умолчанию "arp", но можно переопределить.
	BPF string
}

func SniffARP(ctx context.Context, opts SniffOptions, cb func(core.ARPEvent)) error {
	if cb == nil {
		return fmt.Errorf("sniff: callback is nil")
	}
	if opts.BPF == "" {
		opts.BPF = "arp"
	}
	if opts.ReadTimeout == 0 {
		opts.ReadTimeout = 500 * time.Millisecond
	}

	h, err := core.OpenPcapHandle(core.CaptureOptions{
		Iface:   opts.Iface,
		SnapLen: opts.SnapLen,
		Promisc: opts.Promisc,
		Timeout: opts.ReadTimeout,
	})
	if err != nil {
		return err
	}
	defer h.Close()

	if err := core.SetBPF(h, opts.BPF); err != nil {
		return err
	}

	// Variant without PacketSource: less magic, easier to handle timeouts.
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		data, ci, err := h.ReadPacketData()
		if err != nil {
			// Read timeout in libpcap is usually returned as pcap.NextErrorTimeoutExpired.
			if err == pcap.NextErrorTimeoutExpired {
				continue
			}
			return fmt.Errorf("pcap read: %w", err)
		}

		// Decode only what we need.
		p := gopacket.NewPacket(data, h.LinkType(), gopacket.NoCopy)
		// Set timestamp from CaptureInfo (Packet.Metadata() is sometimes empty when manually creating NewPacket).
		// Therefore: if DecodeARPEvent returns zero Timestamp, substitute with ci.Timestamp.
		e, ok := core.DecodeARPEvent(p)
		if !ok {
			continue
		}
		if e.Timestamp.IsZero() {
			e.Timestamp = ci.Timestamp
		}

		cb(e)
	}
}
