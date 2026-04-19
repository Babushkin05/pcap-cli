package main

import (
	"fmt"
	"math/rand"
	"net"
	"time"

	"github.com/Babushkin05/pcap-cli/internal/dns"
	"github.com/spf13/cobra"
)

func newDnsRootCmd(app *App) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "dns-root [domain]",
		Short: "Query root DNS servers for a domain",
		Long:  `Query root DNS servers for IP addresses of specified domains.`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			domain := args[0]

			// Root DNS servers (actual root server IPs)
			// In real implementation, you'd get the current list from https://www.root-servers.org/
			rootServers := []string{
				"198.41.0.4",    // a.root-servers.net
				"199.9.14.201",  // b.root-servers.net
				"192.33.4.12",   // c.root-servers.net
				"199.7.91.13",   // d.root-servers.net
				"192.203.230.10", // e.root-servers.net
			}

			// Pick a random root server
			rand.Seed(time.Now().UnixNano())
			selectedRootServer := rootServers[rand.Intn(len(rootServers))]

			client := dns.NewDNSClient(app.Cfg.Iface, 10*time.Second)

			fmt.Fprintf(cmd.OutOrStdout(), "Querying root server %s for domain: %s\n", selectedRootServer, domain)

			query, err := client.QueryRootServer(selectedRootServer, domain)
			if err != nil {
				return fmt.Errorf("failed to query root server: %v", err)
			}

			if query != nil {
				fmt.Fprintf(cmd.OutOrStdout(), "Received response from root server:\n")

				// Print basic information about the response
				fmt.Fprintf(cmd.OutOrStdout(), "ID: %d, QR: %d, OpCode: %d, RCODE: %d\n",
					query.Header.ID, query.Header.QR, query.Header.OpCode, query.Header.RCODE)
				fmt.Fprintf(cmd.OutOrStdout(), "Questions: %d, Answers: %d, Authority: %d, Additional: %d\n",
					query.Header.QDCount, query.Header.ANCount, query.Header.NSCount, query.Header.ARCount)

				// Print question section
				for _, question := range query.Questions {
					fmt.Fprintf(cmd.OutOrStdout(), "Question: %s (type %d, class %d)\n",
						question.Name, question.Type, question.Class)
				}

				// Print answer section
				for _, answer := range query.Answers {
					fmt.Fprintf(cmd.OutOrStdout(), "Answer: %s (type %d, TTL %d)\n",
						answer.Name, answer.Type, answer.TTL)
				}

				// Print authority section
				for _, auth := range query.Authority {
					fmt.Fprintf(cmd.OutOrStdout(), "Authority: %s (type %d)\n",
						auth.Name, auth.Type)
				}

				// Print additional section
				for _, add := range query.Additional {
					fmt.Fprintf(cmd.OutOrStdout(), "Additional: %s (type %d)\n",
						add.Name, add.Type)
				}
			} else {
				fmt.Fprintf(cmd.OutOrStdout(), "No response from root server\n")
			}

			// Additionally, let's compare with a regular DNS server (your ISP's DNS)
			fmt.Fprintf(cmd.OutOrStdout(), "\nComparing with regular DNS server response:\n")

			// Get system DNS resolver response for comparison
			sysIPs, err := net.LookupIP(domain)
			if err != nil {
				fmt.Fprintf(cmd.OutOrStdout(), "System DNS lookup error: %v\n", err)
			} else {
				fmt.Fprintf(cmd.OutOrStdout(), "System DNS returned %d IP(s):\n", len(sysIPs))
				for _, ip := range sysIPs {
					fmt.Fprintf(cmd.OutOrStdout(), "  %s\n", ip.String())
				}
			}

			fmt.Fprintf(cmd.OutOrStdout(), "\nAnalysis:\n")
			fmt.Fprintf(cmd.OutOrStdout(), "- Root server typically provides referral to TLD servers,\n")
			fmt.Fprintf(cmd.OutOrStdout(), "  while your local DNS server provides the final answer after resolving the full chain.\n")
			fmt.Fprintf(cmd.OutOrStdout(), "- Root servers may not directly resolve end-user domains,\n")
			fmt.Fprintf(cmd.OutOrStdout(), "  instead providing pointers to more specific name servers.\n")

			return nil
		},
	}

	return cmd
}