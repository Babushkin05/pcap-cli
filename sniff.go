package main

import (
	"context"
	"fmt"
	"time"

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

func SniffARP(ctx context.Context, opts SniffOptions, cb func(ARPEvent)) error {
	if cb == nil {
		return fmt.Errorf("sniff: callback is nil")
	}
	if opts.BPF == "" {
		opts.BPF = "arp"
	}
	if opts.ReadTimeout == 0 {
		opts.ReadTimeout = 500 * time.Millisecond
	}

	h, err := OpenPcapHandle(CaptureOptions{
		Iface:   opts.Iface,
		SnapLen: opts.SnapLen,
		Promisc: opts.Promisc,
		Timeout: opts.ReadTimeout,
	})
	if err != nil {
		return err
	}
	defer h.Close()

	if err := SetBPF(h, opts.BPF); err != nil {
		return err
	}

	// Вариант без PacketSource: меньше магии, проще обрабатывать таймауты.
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		data, ci, err := h.ReadPacketData()
		if err != nil {
			// Таймаут чтения в libpcap обычно возвращается как pcap.NextErrorTimeoutExpired.
			if err == pcap.NextErrorTimeoutExpired {
				continue
			}
			return fmt.Errorf("pcap read: %w", err)
		}

		// Декодируем только то, что нужно.
		p := gopacket.NewPacket(data, h.LinkType(), gopacket.NoCopy)
		// Проставим timestamp из CaptureInfo (Packet.Metadata() иногда пустой при ручном NewPacket).
		// Поэтому: если DecodeARPEvent вернул нулевой Timestamp, подставим ci.Timestamp.
		e, ok := DecodeARPEvent(p)
		if !ok {
			continue
		}
		if e.Timestamp.IsZero() {
			e.Timestamp = ci.Timestamp
		}

		cb(e)
	}
}
