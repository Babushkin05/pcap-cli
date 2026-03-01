package main

import (
	"fmt"

	"github.com/Babushkin05/pcap-cli/config"
	"github.com/spf13/cobra"
)

type App struct {
	ConfigPath string
	Cfg        config.Config
}

func newRootCmd() *cobra.Command {
	app := &App{}

	cmd := &cobra.Command{
		Use:   "arpcli",
		Short: "ARP CLI (pcap + gopacket)",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if app.ConfigPath == "" {
				return fmt.Errorf("--config is required")
			}
			cfg, err := config.LoadConfig(app.ConfigPath)
			if err != nil {
				return err
			}
			app.Cfg = cfg
			return nil
		},
	}

	cmd.PersistentFlags().StringVar(&app.ConfigPath, "config", "", "Path to YAML config")

	// Subcommands
	cmd.AddCommand(newSniffCmd(app))
	cmd.AddCommand(newRouterMACCmd(app))
	cmd.AddCommand(newStatsCmd(app))

	return cmd
}
