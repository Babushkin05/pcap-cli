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

		// Decode Ethernet (for counting frames/bytes/unique/broadcast).
		p := gopacket.NewPacket(data, h.LinkType(), gopacket.NoCopy)

		ethL := p.Layer(layers.LayerTypeEthernet)
		if ethL == nil {
			// On macOS en0 Ethernet layer will usually be present.
			// If not, we can extend support to SLL and others.
			continue
		}
		eth := ethL.(*layers.Ethernet)

		// frameLen: take ci.Length (original packet length according to pcap)
		sc.ObserveEthernet(ci.Timestamp, eth.SrcMAC, eth.DstMAC, ci.Length)

		// If this is ARP — update ARP statistics.
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
