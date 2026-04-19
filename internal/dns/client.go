package dns

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
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
	// Note: In a real implementation, you would get the actual IP/MAC from the interface
	return &DNSClient{
		interfaceName: interfaceName,
		timeout:       timeout,
	}
}

// Query sends a DNS query and waits for response
func (c *DNSClient) Query(serverIP, domain string, qtype uint16) (*DNSQuery, error) {
	// Open the interface for sending and receiving packets
	handle, err := pcap.OpenLive(c.interfaceName, 65536, true, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("failed to open interface %s: %v", c.interfaceName, err)
	}
	defer handle.Close()

	// Generate a random ID for this transaction
	id := uint16(time.Now().UnixMilli() & 0xFFFF)

	// Create the DNS query packet
	queryBytes := c.buildDNSQuery(id, domain, qtype)

	// Create the full packet with Ethernet, IP, and UDP headers
	fullPacket, err := c.buildFullPacket(serverIP, queryBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to build full packet: %v", err)
	}

	// Create a goroutine to send the query
	errCh := make(chan error, 1)
	go func() {
		defer close(errCh)

		// Send the complete packet
		if err := handle.WritePacketData(fullPacket); err != nil {
			errCh <- fmt.Errorf("failed to send DNS query: %v", err)
			return
		}
	}()

	// Create a goroutine to receive the response
	responseCh := make(chan *DNSQuery, 1)
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()

	go func() {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

		for {
			select {
			case <-ctx.Done():
				return
			case packet := <-packetSource.Packets():
				if packet == nil {
					continue
				}

				// Check if this is a UDP packet
				udpLayer := packet.Layer(layers.LayerTypeUDP)
				if udpLayer == nil {
					continue
				}

				udp, _ := udpLayer.(*layers.UDP)

				// Check if it's a response to our query (coming from DNS server port 53)
				if udp.SrcPort != 53 {
					continue
				}

				// Parse the DNS response
				dnsQuery, err := ParseDNSPacketWithAllSections(udp.Payload)
				if err != nil {
					continue
				}

				// Check if the ID matches our query
				if dnsQuery.Header.ID == id {
					responseCh <- dnsQuery
					return
				}
			}
		}
	}()

	// Wait for either the response or an error
	select {
	case err := <-errCh:
		if err != nil {
			return nil, err
		}
	case response := <-responseCh:
		return response, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("timeout waiting for DNS response")
	}

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
func (c *DNSClient) buildFullPacket(destIP string, dnsQuery []byte) ([]byte, error) {
	// For this implementation, we'll create the layers using gopacket
	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	// This is a simplified implementation - in reality, we'd need to handle:
	// - Proper MAC address resolution
	// - IP addressing

	// Create layers
	ip := net.ParseIP(destIP)
	if ip == nil {
		return nil, fmt.Errorf("invalid destination IP: %s", destIP)
	}

	ethernetLayer := &layers.Ethernet{
		SrcMAC:       nil, // Will be filled by the interface
		DstMAC:       nil, // Will be filled by ARP resolution
		EthernetType: layers.EthernetTypeIPv4,
	}

	ipLayer := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		SrcIP:    nil, // Will be filled by the interface
		DstIP:    ip.To4(),
		Protocol: layers.IPProtocolUDP,
	}

	udpLayer := &layers.UDP{
		SrcPort: layers.UDPPort(12345), // Random source port
		DstPort: layers.UDPPort(53),    // Standard DNS port
	}

	// Set the UDP payload (our DNS query)
	udpLayer.Payload = dnsQuery

	// Compute checksums and lengths
	if err := udpLayer.SetNetworkLayerForChecksum(ipLayer); err != nil {
		return nil, fmt.Errorf("failed to set network layer for UDP checksum: %v", err)
	}

	// Serialize the packet
	err := gopacket.SerializeLayers(buffer, opts, ethernetLayer, ipLayer, udpLayer)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize packet: %v", err)
	}

	return buffer.Bytes(), nil
}

// ParseDNSPacketWithAllSections parses a DNS packet and extracts all sections
func ParseDNSPacketWithAllSections(data []byte) (*DNSQuery, error) {
	if len(data) < 12 {
		return nil, fmt.Errorf("DNS packet too short")
	}

	query := &DNSQuery{
		Header: DNSHeader{
			ID:      binary.BigEndian.Uint16(data[0:2]),
			QR:      (binary.BigEndian.Uint16(data[2:4]) >> 15) & 0x01,
			OpCode:  (binary.BigEndian.Uint16(data[2:4]) >> 11) & 0x0F,
			AA:      (binary.BigEndian.Uint16(data[2:4]) >> 10) & 0x01,
			TC:      (binary.BigEndian.Uint16(data[2:4]) >> 9) & 0x01,
			RD:      (binary.BigEndian.Uint16(data[2:4]) >> 8) & 0x01,
			RA:      (binary.BigEndian.Uint16(data[2:4]) >> 7) & 0x01,
			Z:       (binary.BigEndian.Uint16(data[2:4]) >> 4) & 0x07,
			RCODE:   binary.BigEndian.Uint16(data[2:4]) & 0x0F,
			QDCount: binary.BigEndian.Uint16(data[4:6]),
			ANCount: binary.BigEndian.Uint16(data[6:8]),
			NSCount: binary.BigEndian.Uint16(data[8:10]),
			ARCount: binary.BigEndian.Uint16(data[10:12]),
		},
	}

	currentPos := 12

	// Parse questions
	for i := uint16(0); i < query.Header.QDCount; i++ {
		question, newPos, err := ParseDNSQuestion(data, currentPos)
		if err != nil {
			break // Continue with partial results
		}
		query.Questions = append(query.Questions, question)
		currentPos = newPos
	}

	// Parse answers
	for i := uint16(0); i < query.Header.ANCount; i++ {
		record, newPos, err := ParseDNSResourceRecord(data, currentPos)
		if err != nil {
			break // Continue with partial results
		}
		query.Answers = append(query.Answers, record)
		currentPos = newPos
	}

	// Parse authority records
	for i := uint16(0); i < query.Header.NSCount; i++ {
		record, newPos, err := ParseDNSResourceRecord(data, currentPos)
		if err != nil {
			break // Continue with partial results
		}
		query.Authority = append(query.Authority, record)
		currentPos = newPos
	}

	// Parse additional records
	for i := uint16(0); i < query.Header.ARCount; i++ {
		record, newPos, err := ParseDNSResourceRecord(data, currentPos)
		if err != nil {
			break // Continue with partial results
		}
		query.Additional = append(query.Additional, record)
		currentPos = newPos
	}

	return query, nil
}

// LookupMX performs an MX record lookup for a domain
func (c *DNSClient) LookupMX(domain string, dnsServer string) ([]MXRecord, error) {
	query, err := c.Query(dnsServer, domain, 15) // 15 is the type for MX records
	if err != nil {
		return nil, fmt.Errorf("failed to lookup MX record for %s: %v", domain, err)
	}

	// Parse the response to extract MX records
	mxRecords := []MXRecord{}

	// Look for MX records in the answer section
	for _, answer := range query.Answers {
		if answer.Type == 15 { // MX record type
			// Parse MX record format: preference (2 bytes) + domain name
			if len(answer.RData) >= 2 {
				preference := binary.BigEndian.Uint16(answer.RData[0:2])

				// Parse the exchange domain name from the RData
				exchange, _, err := parseDomainName(answer.RData, 2)
				if err != nil {
					fmt.Printf("Error parsing MX exchange name: %v\n", err)
					continue
				}

				// In a real implementation, you would need to resolve the exchange name to an IP
				// For now, we'll add a placeholder
				mxRecord := MXRecord{
					Preference: preference,
					Exchange:   exchange,
					Address:    net.ParseIP("0.0.0.0"), // Placeholder
				}

				mxRecords = append(mxRecords, mxRecord)
			}
		}
	}

	return mxRecords, nil
}

// QueryRootServer queries a root DNS server for an address
func (c *DNSClient) QueryRootServer(rootServerIP, domain string) (*DNSQuery, error) {
	return c.Query(rootServerIP, domain, 1) // 1 is the type for A records
}