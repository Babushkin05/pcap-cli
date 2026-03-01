package stats

import (
	"fmt"
	"net"
	"time"

	"github.com/Babushkin05/pcap-cli/internal/core"
)

type Stats struct {
	Start time.Time
	End   time.Time

	TotalEtherFrames int
	TotalARPPackets  int

	UniqueMACs map[string]struct{}

	BroadcastEther int
	BroadcastARP   int

	GratuitousARPRequests int

	ARPPairsMatched int

	BytesMyRouter int64 // total in both directions
	Drops         int   // from pcap stats (if possible)
}

type StatsCollector struct {
	myMAC     net.HardwareAddr
	routerMAC net.HardwareAddr

	countPaddingTo60 bool

	corr *core.ARPCorrelator
	s    Stats
}

type StatsOptions struct {
	MyMAC     net.HardwareAddr
	RouterMAC net.HardwareAddr

	PairWindow time.Duration

	CountEtherPaddingTo60 bool
}

func NewStatsCollector(opts StatsOptions) (*StatsCollector, error) {
	if len(opts.MyMAC) != 6 {
		return nil, fmt.Errorf("stats: MyMAC must be 6 bytes")
	}
	if len(opts.RouterMAC) != 6 {
		return nil, fmt.Errorf("stats: RouterMAC must be 6 bytes")
	}

	sc := &StatsCollector{
		myMAC:            append(net.HardwareAddr(nil), opts.MyMAC...),
		routerMAC:        append(net.HardwareAddr(nil), opts.RouterMAC...),
		countPaddingTo60: opts.CountEtherPaddingTo60,
		corr:             core.NewARPCorrelator(opts.PairWindow),
		s: Stats{
			UniqueMACs: make(map[string]struct{}),
		},
	}
	return sc, nil
}

func (sc *StatsCollector) Start(t time.Time) {
	sc.s.Start = t
}

func (sc *StatsCollector) End(t time.Time) {
	sc.s.End = t
	sc.s.ARPPairsMatched = sc.corr.MatchedPairs()
}

func (sc *StatsCollector) SetDrops(d int) {
	sc.s.Drops = d
}

func (sc *StatsCollector) ObserveEthernet(ts time.Time, src, dst net.HardwareAddr, frameLen int) {
	sc.s.TotalEtherFrames++

	// unique MAC: usually count src and dst
	if len(src) == 6 {
		sc.s.UniqueMACs[src.String()] = struct{}{}
	}
	if len(dst) == 6 {
		sc.s.UniqueMACs[dst.String()] = struct{}{}
	}

	if core.IsBroadcastMAC(dst) {
		sc.s.BroadcastEther++
	}

	// bytes between my device and router (L2)
	if len(src) == 6 && len(dst) == 6 {
		if (src.String() == sc.myMAC.String() && dst.String() == sc.routerMAC.String()) ||
			(src.String() == sc.routerMAC.String() && dst.String() == sc.myMAC.String()) {

			n := frameLen
			if sc.countPaddingTo60 && n > 0 && n < 60 {
				n = 60
			}
			if n > 0 {
				sc.s.BytesMyRouter += int64(n)
			}
		}
	}

	// periodically clean pending to prevent growth
	sc.corr.Cleanup(ts)
}

func (sc *StatsCollector) ObserveARP(e core.ARPEvent) {
	sc.s.TotalARPPackets++

	if core.IsBroadcastMAC(e.DstMAC) {
		sc.s.BroadcastARP++
	}
	if core.IsGratuitousARPRequest(e) {
		sc.s.GratuitousARPRequests++
	}

	sc.corr.OnARP(e)
}

func (sc *StatsCollector) Snapshot() Stats {
	// return copy (map left as is or copied — for CLI not critical)
	return sc.s
}
