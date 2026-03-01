package stats

import (
	"context"
	"fmt"
	"time"

	"github.com/Babushkin05/pcap-cli/internal/core"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type CaptureStatsOptions struct {
	Iface       string
	SnapLen     int
	Promisc     bool
	ReadTimeout time.Duration
	Duration    time.Duration
}

func CaptureStats(ctx context.Context, opts CaptureStatsOptions, sc *StatsCollector) (Stats, error) {
	if sc == nil {
		return Stats{}, fmt.Errorf("capture stats: StatsCollector is nil")
	}
	if opts.Duration <= 0 {
		return Stats{}, fmt.Errorf("capture stats: duration must be > 0")
	}
	if opts.ReadTimeout == 0 {
		opts.ReadTimeout = 200 * time.Millisecond
	}

	h, err := core.OpenPcapHandle(core.CaptureOptions{
		Iface:   opts.Iface,
		SnapLen: opts.SnapLen,
		Promisc: opts.Promisc,
		Timeout: opts.ReadTimeout,
	})
	if err != nil {
		return Stats{}, err
	}
	defer h.Close()

	start := time.Now()
	end := start.Add(opts.Duration)
	sc.Start(start)

	for time.Now().Before(end) {
		select {
		case <-ctx.Done():
			return Stats{}, ctx.Err()
		default:
		}

		data, ci, err := h.ReadPacketData()
		if err != nil {
			if err == pcap.NextErrorTimeoutExpired {
				continue
			}
			return Stats{}, fmt.Errorf("capture stats: read packet: %w", err)
		}

		// Декодируем Ethernet (для подсчёта фреймов/байт/unique/broadcast).
		p := gopacket.NewPacket(data, h.LinkType(), gopacket.NoCopy)

		ethL := p.Layer(layers.LayerTypeEthernet)
		if ethL == nil {
			// На macOS en0 обычно Ethernet layer будет.
			// Если нет — можно будет расширить под SLL и т.п.
			continue
		}
		eth := ethL.(*layers.Ethernet)

		// frameLen: берём ci.Length (оригинальная длина пакета по мнению pcap)
		sc.ObserveEthernet(ci.Timestamp, eth.SrcMAC, eth.DstMAC, ci.Length)

		// Если это ARP — обновляем ARP-статистику.
		if e, ok := core.DecodeARPEvent(p); ok {
			if e.Timestamp.IsZero() {
				e.Timestamp = ci.Timestamp
			}
			sc.ObserveARP(e)
		}
	}

	// pcap drops
	if ps, err := h.Stats(); err == nil {
		sc.SetDrops(int(ps.PacketsDropped))
	}

	sc.End(time.Now())
	return sc.Snapshot(), nil
}
