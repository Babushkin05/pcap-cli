package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

type App struct {
	ConfigPath string
	Cfg        Config
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
			cfg, err := LoadConfig(app.ConfigPath)
			if err != nil {
				return err
			}
			app.Cfg = cfg
			return nil
		},
	}

	cmd.PersistentFlags().StringVar(&app.ConfigPath, "config", "", "Path to YAML config")

	// Подкоманды
	cmd.AddCommand(newSniffCmd(app))
	cmd.AddCommand(newRouterMACCmd(app))
	cmd.AddCommand(newStatsCmd(app))

	return cmd
}
