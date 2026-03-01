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

func newSniffCmd(app *App) *cobra.Command {
	var promisc bool
	var snaplen int

	cmd := &cobra.Command{
		Use:   "sniff",
		Short: "Capture ARP packets and print them",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			opts := SniffOptions{
				Iface:       app.Cfg.Iface,
				SnapLen:     snaplen,
				Promisc:     promisc,
				ReadTimeout: 500 * time.Millisecond,
				BPF:         "arp",
			}

			return SniffARP(ctx, opts, func(e ARPEvent) {
				fmt.Fprintln(cmd.OutOrStdout(), DescribeARP(e))
			})
		},
	}

	cmd.Flags().BoolVar(&promisc, "promisc", true, "Enable promiscuous mode")
	cmd.Flags().IntVar(&snaplen, "snaplen", 65535, "Snapshot length")

	return cmd
}
