package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Babushkin05/pcap-cli/internal/router_mac"
	"github.com/spf13/cobra"
)

func newRouterMACCmd(app *App) *cobra.Command {
	var force bool
	var promisc bool
	var snaplen int
	var retries int
	var wait time.Duration
	var readTimeout time.Duration

	cmd := &cobra.Command{
		Use:   "router-mac",
		Short: "Resolve router MAC (uses cached router_mac from config unless --force is set)",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			cfg := app.Cfg
			if force {
				cfg.RouterMAC = nil
			}

			mac, err := router_mac.ResolveRouterMAC(ctx, cfg, router_mac.RouterResolveParams{
				SnapLen:     snaplen,
				Promisc:     promisc,
				ReadTimeout: readTimeout,
				WaitPerTry:  wait,
				Retries:     retries,
			})
			if err != nil {
				return err
			}

			fmt.Fprintln(cmd.OutOrStdout(), mac.String())
			return nil
		},
	}

	cmd.Flags().BoolVar(&promisc, "promisc", true, "Enable promiscuous mode")
	cmd.Flags().IntVar(&snaplen, "snaplen", 65535, "Snapshot length")
	cmd.Flags().IntVar(&retries, "retries", 2, "How many ARP request attempts")
	cmd.Flags().DurationVar(&wait, "wait", 1500*time.Millisecond, "How long to wait for reply per attempt")
	cmd.Flags().DurationVar(&readTimeout, "read-timeout", 200*time.Millisecond, "pcap read timeout (for ctx cancellation responsiveness)")

	return cmd
}
