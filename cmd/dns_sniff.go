package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Babushkin05/pcap-cli/internal/dns"
	"github.com/spf13/cobra"
)

func newDnsSniffCmd(app *App) *cobra.Command {
	var promisc bool
	var snaplen int
	var duration time.Duration

	cmd := &cobra.Command{
		Use:   "dns-sniff",
		Short: "Capture DNS packets and print them",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			dnsCfg := dns.DNSConfig{
				InterfaceName: app.Cfg.Iface,
				Timeout:       30 * time.Second,
			}

			sniffer := dns.NewDNSSniffer(dnsCfg)

			// Set up a channel to receive captured packets
			done := make(chan error, 1)

			go func() {
				err := sniffer.SniffDNS(ctx, func(query dns.DNSQuery) {
					fmt.Fprintln(cmd.OutOrStdout(), dns.FormatDNSQuery(&query))
				})
				done <- err
			}()

			// Wait for either context cancellation or an error
			select {
			case <-ctx.Done():
				fmt.Fprintln(cmd.OutOrStdout(), "DNS sniffing stopped")
				return nil
			case err := <-done:
				return err
			}
		},
	}

	cmd.Flags().BoolVar(&promisc, "promisc", true, "Enable promiscuous mode")
	cmd.Flags().IntVar(&snaplen, "snaplen", 65535, "Snapshot length")
	cmd.Flags().DurationVar(&duration, "duration", 0, "How long to capture (0 = infinite)")

	return cmd
}