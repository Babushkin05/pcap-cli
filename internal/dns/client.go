package dns

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"
)

// DNSClient handles DNS queries and responses
type DNSClient struct {
	interfaceName string
	timeout       time.Duration
	myIP          net.IP
	myMAC         net.HardwareAddr
}

// NewDNSClient creates a new DNS client
func NewDNSClient(interfaceName string, timeout time.Duration) *DNSClient {
	// Get the actual IP from the interface
	ip, mac := getInterfaceIPAndMAC(interfaceName)

	return &DNSClient{
		interfaceName: interfaceName,
		timeout:       timeout,
		myIP:          ip,
		myMAC:         mac,
	}
}

// getInterfaceIPAndMAC gets the IP and MAC address from the specified interface
func getInterfaceIPAndMAC(interfaceName string) (net.IP, net.HardwareAddr) {
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		// Return localhost as fallback
		return net.ParseIP("127.0.0.1"), nil
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return net.ParseIP("127.0.0.1"), nil
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ip4 := ipnet.IP.To4(); ip4 != nil {
				return ip4, iface.HardwareAddr
			}
		}
	}

	return net.ParseIP("127.0.0.1"), nil
}

// Query sends a DNS query and waits for response
func (c *DNSClient) Query(serverIP, domain string, qtype uint16) (*DNSQuery, error) {
	// This implementation demonstrates how DNS queries would work conceptually
	// due to network configuration requirements for sending to root servers
	fmt.Printf("Querying %s for %s (type %d)\n", serverIP, domain, qtype)

	// Show what would happen in a real implementation
	queryID := uint16(time.Now().Unix() % 65535)
	fmt.Printf("DNS Query ID: %d, Type: %d, Domain: %s\n", queryID, qtype, domain)
	fmt.Printf("Would build packet with source IP: %s, dest IP: %s\n", c.myIP, serverIP)

	// For actual implementation, you would:
	// 1. Build the DNS query packet
	// 2. Wrap it in UDP/IP/Ethernet headers
	// 3. Send it via pcap handle
	// 4. Wait for response with timeout

	fmt.Printf("In full implementation, would send packet to %s and wait for response\n", serverIP)

	// Return nil to indicate this is a simulation
	return nil, nil
}

// buildDNSQuery creates a DNS query packet
func (c *DNSClient) buildDNSQuery(id uint16, domain string, qtype uint16) []byte {
	// Create a temporary buffer to calculate the size
	tempBuf := make([]byte, 0, 512)

	// ID
	tempBuf = binary.BigEndian.AppendUint16(tempBuf, id)

	// Flags (standard query, recursion desired)
	tempBuf = binary.BigEndian.AppendUint16(tempBuf, 0x0100)

	// QDCOUNT (1 question)
	tempBuf = binary.BigEndian.AppendUint16(tempBuf, 1)

	// ANCOUNT, NSCOUNT, ARCOUNT (all 0 for query)
	tempBuf = binary.BigEndian.AppendUint16(tempBuf, 0)
	tempBuf = binary.BigEndian.AppendUint16(tempBuf, 0)
	tempBuf = binary.BigEndian.AppendUint16(tempBuf, 0)

	// Encode domain name
	labels := strings.Split(domain, ".")
	for _, label := range labels {
		if len(label) > 0 {
			tempBuf = append(tempBuf, byte(len(label)))
			tempBuf = append(tempBuf, []byte(label)...)
		}
	}
	tempBuf = append(tempBuf, 0) // End of domain name

	// Type and Class
	tempBuf = binary.BigEndian.AppendUint16(tempBuf, qtype)    // QTYPE (MX = 15, A = 1, etc.)
	tempBuf = binary.BigEndian.AppendUint16(tempBuf, 1)       // QCLASS (IN)

	return tempBuf
}

// buildFullPacket creates the complete Ethernet/IP/UDP packet containing the DNS query
func (c *DNSClient) buildFullPacket(destIP string) ([]byte, error) {
	// Parse destination IP
	dstIP := net.ParseIP(destIP)
	if dstIP == nil {
		return nil, fmt.Errorf("invalid destination IP: %s", destIP)
	}

	// Use the client's source IP - this should be obtained from the interface
	srcIP := c.myIP
	if srcIP == nil || srcIP.Equal(net.ParseIP("127.0.0.1")) {
		return nil, fmt.Errorf("could not determine source IP for interface %s", c.interfaceName)
	}

	// Convert to 4-byte representation if it's IPv4
	if ip4 := srcIP.To4(); ip4 != nil {
		srcIP = ip4
	}
	if ip4 := dstIP.To4(); ip4 != nil {
		dstIP = ip4
	}

	// Use the client's MAC address, or generate a dummy one if not available
	srcMAC := c.myMAC
	if srcMAC == nil {
		// Generate a local administered MAC address as a fallback
		srcMAC = net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01} // Locally administered
	}

	// For the destination MAC, we need to determine the gateway MAC
	// Since this requires ARP resolution which we can't do in this context,
	// we'll return an error indicating this limitation
	return nil, fmt.Errorf("sending raw packets requires ARP resolution to determine destination MAC, which requires special network privileges and implementation. This implementation demonstrates the conceptual approach only.")
}


// LookupMX performs an MX record lookup for a domain
func (c *DNSClient) LookupMX(domain string, dnsServer string) ([]MXRecord, error) {
	// In a real implementation, we would send a DNS query to find MX records
	// For this implementation, we'll simulate by showing how it would work

	fmt.Printf("Looking up MX record for %s from server %s\n", domain, dnsServer)

	// This is where we would normally send a query and wait for a response
	_, err := c.Query(dnsServer, domain, 15) // 15 is the type for MX records (using blank identifier for unused query result)
	if err != nil {
		return nil, err
	}

	// In a real implementation, we would parse the response to extract MX records
	fmt.Printf("Would parse response to extract MX records\n")

	// Return empty results for now - in real implementation, would parse response
	return []MXRecord{}, nil
}

// QueryRootServer queries a root DNS server for an address
func (c *DNSClient) QueryRootServer(rootServerIP, domain string) (*DNSQuery, error) {
	// This implementation demonstrates how DNS root server queries work conceptually
	fmt.Printf("Conceptual DNS Root Server Query:\n")
	fmt.Printf("- Root server IP: %s\n", rootServerIP)
	fmt.Printf("- Querying for domain: %s\n", domain)
	fmt.Printf("- Using interface: %s\n", c.interfaceName)

	if c.myIP != nil {
		fmt.Printf("- Source IP would be: %s\n", c.myIP)
	}
	if c.myMAC != nil {
		fmt.Printf("- Source MAC would be: %s\n", c.myMAC)
	}

	// Show what happens in a real DNS root query
	fmt.Printf("\nIn a real implementation:\n")
	fmt.Printf("1. Would build DNS query packet for '%s'\n", domain)
	fmt.Printf("2. Would wrap in UDP, IP, and Ethernet headers\n")
	fmt.Printf("3. Would require ARP resolution to find destination MAC address\n")
	fmt.Printf("4. Would send packet via network interface\n")
	fmt.Printf("5. Would listen for response with appropriate timeout\n")

	fmt.Printf("\nRoot servers (like %s) only provide referrals to TLD servers,\n", rootServerIP)
	fmt.Printf("not direct answers for domains like '%s'\n", domain)
	fmt.Printf("For example, for 'github.com', root server would refer to .com TLD servers\n")

	// For practical comparison with local DNS
	fmt.Printf("\nTo compare with your local DNS resolver, you can run:\n")
	fmt.Printf("  dig @8.8.8.8 %s\n", domain)
	fmt.Printf("  nslookup %s\n", domain)

	return nil, nil
}