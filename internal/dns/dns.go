package dns

import (
	"context"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// DNSSniffer handles DNS packet capturing
type DNSSniffer struct {
	config DNSConfig
}

// NewDNSSniffer creates a new DNS sniffer
func NewDNSSniffer(config DNSConfig) *DNSSniffer {
	return &DNSSniffer{
		config: config,
	}
}

// SniffDNS captures and processes DNS packets
func (d *DNSSniffer) SniffDNS(ctx context.Context, callback func(DNSQuery)) error {
	handle, err := pcap.OpenLive(d.config.InterfaceName, 65536, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("failed to open interface %s: %v", d.config.InterfaceName, err)
	}
	defer handle.Close()

	// Set BPF filter to capture only DNS traffic
	err = handle.SetBPFFilter("udp port 53")
	if err != nil {
		return fmt.Errorf("failed to set BPF filter: %v", err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for {
		select {
		case <-ctx.Done():
			return nil
		case packet := <-packetSource.Packets():
			if packet == nil {
				continue
			}

			// Extract UDP layer
			udpLayer := packet.Layer(layers.LayerTypeUDP)
			if udpLayer == nil {
				continue
			}
			udp, _ := udpLayer.(*layers.UDP)

			// Process DNS payload
			query, err := ParseDNSPacket(udp.Payload)
			if err != nil {
				continue // Not a valid DNS packet
			}

			callback(*query)
		}
	}
}

// ParseDNSQuestion parses a DNS question from raw data
func ParseDNSQuestion(data []byte, offset int) (question DNSQuestion, newOffset int, err error) {
	name, newOffset, err := parseDomainName(data, offset)
	if err != nil {
		return question, newOffset, err
	}

	if newOffset+4 > len(data) {
		return question, newOffset, fmt.Errorf("not enough data for DNS question")
	}

	qtype := binary.BigEndian.Uint16(data[newOffset : newOffset+2])
	qclass := binary.BigEndian.Uint16(data[newOffset+2 : newOffset+4])

	question = DNSQuestion{
		Name:  name,
		Type:  qtype,
		Class: qclass,
	}

	return question, newOffset + 4, nil
}

// ParseDNSResourceRecord parses a DNS resource record from raw data
func ParseDNSResourceRecord(data []byte, offset int) (DNSResourceRecord, int, error) {
	name, newOffset, err := parseDomainName(data, offset)
	if err != nil {
		return DNSResourceRecord{}, offset, err
	}

	if newOffset+10 > len(data) {
		return DNSResourceRecord{}, offset, fmt.Errorf("not enough data for DNS resource record")
	}

	rt := binary.BigEndian.Uint16(data[newOffset : newOffset+2])
	class := binary.BigEndian.Uint16(data[newOffset+2 : newOffset+4])
	ttl := binary.BigEndian.Uint32(data[newOffset+4 : newOffset+8])
	rdlen := binary.BigEndian.Uint16(data[newOffset+8 : newOffset+10])

	newOffset += 10

	if newOffset+int(rdlen) > len(data) {
		return DNSResourceRecord{}, offset, fmt.Errorf("not enough data for DNS resource record RDATA")
	}

	rdata := make([]byte, rdlen)
	copy(rdata, data[newOffset:newOffset+int(rdlen)])

	newOffset += int(rdlen)

	record := DNSResourceRecord{
		Name:  name,
		Type:  rt,
		Class: class,
		TTL:   ttl,
		RDLen: rdlen,
		RData: rdata,
	}

	return record, newOffset, nil
}

// parseDomainName parses a domain name from DNS packet
func parseDomainName(data []byte, offset int) (string, int, error) {
	if offset >= len(data) {
		return "", offset, fmt.Errorf("offset exceeds data length")
	}

	var parts []string
	currentPos := offset

	for {
		if currentPos >= len(data) {
			return "", offset, fmt.Errorf("invalid domain name")
		}

		length := int(data[currentPos])
		if length == 0 {
			// End of domain name
			currentPos++
			break
		}

		if length&0xC0 == 0xC0 {
			// Compressed format
			if currentPos+1 >= len(data) {
				return "", offset, fmt.Errorf("invalid compressed domain name")
			}
			ptr := int(data[currentPos]&0x3F)<<8 | int(data[currentPos+1])
			currentPos += 2

			// Recursively parse the referenced part
			name, _, err := parseDomainName(data, ptr)
			if err != nil {
				return "", offset, err
			}

			joinedParts := strings.Join(parts, ".") + "." + name
			return joinedParts, currentPos, nil
		} else {
			// Regular label
			currentPos++
			if currentPos+length > len(data) {
				return "", offset, fmt.Errorf("domain label exceeds data length")
			}

			parts = append(parts, string(data[currentPos:currentPos+length]))
			currentPos += length
		}
	}

	return strings.Join(parts, "."), currentPos, nil
}

// ParseDNSPacket parses a raw packet and extracts DNS information
func ParseDNSPacket(data []byte) (*DNSQuery, error) {
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

	return query, nil
}

// FormatDNSQuery formats a DNS query for display
func FormatDNSQuery(query *DNSQuery) string {
	result := fmt.Sprintf("DNS Query ID: %d, QR: %d, OpCode: %d, QDCount: %d, ANCount: %d, NSCount: %d, ARCount: %d",
		query.Header.ID, query.Header.QR, query.Header.OpCode,
		query.Header.QDCount, query.Header.ANCount, query.Header.NSCount, query.Header.ARCount)

	// Add question information if available
	for _, question := range query.Questions {
		result += fmt.Sprintf("\n  Question: %s (type %d, class %d)", question.Name, question.Type, question.Class)
	}

	return result
}

// LookupMX finds mail exchange records for a domain
func (d *DNSSniffer) LookupMX(domain string) ([]MXRecord, error) {
	// This would normally send a DNS query to find MX records
	// For now, we'll return a placeholder - in real implementation,
	// this would send a proper DNS query to find MX records

	fmt.Printf("Looking up MX record for: %s\n", domain)

	// Return an empty slice - actual implementation would involve sending a DNS query
	// and parsing the response to extract MX records
	return []MXRecord{}, nil
}

// QueryRootServer queries a root DNS server for an address
func (d *DNSSniffer) QueryRootServer(server, domain string) (*DNSQuery, error) {
	// This would send a DNS query to a root server
	// For now, we'll return a placeholder - in real implementation,
	// this would connect to the root server and send a DNS query

	fmt.Printf("Querying root server %s for domain: %s\n", server, domain)

	// Return nil - actual implementation would involve connecting to root server
	// and parsing the response
	return nil, nil
}