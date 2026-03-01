package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"
)

func newStatsCmd(app *App) *cobra.Command {
	var duration time.Duration
	var promisc bool
	var snaplen int
	var pairWindow time.Duration
	var pad60 bool

	cmd := &cobra.Command{
		Use:   "stats",
		Short: "Collect Ethernet/ARP statistics for a duration",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(app.Cfg.RouterMAC) != 6 {
				return fmt.Errorf("stats: router_mac is required in config")
			}

			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			sc, err := NewStatsCollector(StatsOptions{
				MyMAC:                 app.Cfg.MyMAC,
				RouterMAC:             app.Cfg.RouterMAC,
				PairWindow:            pairWindow,
				CountEtherPaddingTo60: pad60,
			})
			if err != nil {
				return err
			}

			st, err := CaptureStats(ctx, CaptureStatsOptions{
				Iface:       app.Cfg.Iface,
				SnapLen:     snaplen,
				Promisc:     promisc,
				ReadTimeout: 200 * time.Millisecond,
				Duration:    duration,
			}, sc)
			if err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "Interval: %s .. %s\n", st.Start.Format(time.RFC3339), st.End.Format(time.RFC3339))
			fmt.Fprintf(out, "Ethernet frames: %d\n", st.TotalEtherFrames)
			fmt.Fprintf(out, "ARP packets: %d\n", st.TotalARPPackets)
			fmt.Fprintf(out, "Unique MACs: %d\n", len(st.UniqueMACs))
			fmt.Fprintf(out, "Broadcast Ethernet: %d\n", st.BroadcastEther)
			fmt.Fprintf(out, "Broadcast ARP: %d\n", st.BroadcastARP)
			fmt.Fprintf(out, "Gratuitous ARP requests: %d\n", st.GratuitousARPRequests)
			fmt.Fprintf(out, "ARP request/reply pairs matched: %d\n", st.ARPPairsMatched)
			fmt.Fprintf(out, "Bytes between me and router: %d\n", st.BytesMyRouter)
			fmt.Fprintf(out, "pcap drops: %d\n", st.Drops)

			return nil
		},
	}

	cmd.Flags().DurationVar(&duration, "duration", 30*time.Second, "How long to capture")
	cmd.Flags().BoolVar(&promisc, "promisc", true, "Enable promiscuous mode")
	cmd.Flags().IntVar(&snaplen, "snaplen", 65535, "Snapshot length")
	cmd.Flags().DurationVar(&pairWindow, "pair-window", 3*time.Second, "Max time between ARP request and reply to count as a pair")
	cmd.Flags().BoolVar(&pad60, "pad60", true, "Count Ethernet padding up to 60 bytes (without FCS)")

	return cmd
}
