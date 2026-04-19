package main

import (
	"fmt"
	"time"

	"github.com/Babushkin05/pcap-cli/internal/dns"
	"github.com/spf13/cobra"
)

func newDnsLookupCmd(app *App) *cobra.Command {
	var recordType string

	cmd := &cobra.Command{
		Use:   "dns-lookup [domain]",
		Short: "Lookup DNS records for a domain",
		Long:  `Lookup DNS records for a specified domain and print results.`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			domain := args[0]

			client := dns.NewDNSClient(app.Cfg.Iface, 5*time.Second)

			switch recordType {
			case "MX":
				// For MX records, we might need to first get the nameserver
				// For this implementation, we'll use the system's configured DNS
				// In practice, you might want to use a specific DNS server from config
				mxRecords, err := client.LookupMX(domain, "8.8.8.8")
				if err != nil {
					return fmt.Errorf("failed to lookup MX records: %v", err)
				}

				if len(mxRecords) == 0 {
					fmt.Fprintf(cmd.OutOrStdout(), "No MX records found for %s\n", domain)
				} else {
					for _, mx := range mxRecords {
						// Output format: domain -> IP_address
						fmt.Fprintf(cmd.OutOrStdout(), "%s -> %s (preference: %d)\n", domain, mx.Exchange, mx.Preference)
					}
				}
			default:
				return fmt.Errorf("unsupported record type: %s", recordType)
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&recordType, "type", "t", "MX", "DNS record type to lookup (only MX supported currently)")

	return cmd
}