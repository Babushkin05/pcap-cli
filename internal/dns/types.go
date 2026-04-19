package dns

import (
	"net"
	"time"
)

// DNSHeader represents the header of a DNS packet
type DNSHeader struct {
	ID      uint16
	QR      uint16 // Query/Response flag
	OpCode  uint16
	AA      uint16 // Authoritative Answer
	TC      uint16 // Truncated
	RD      uint16 // Recursion Desired
	RA      uint16 // Recursion Available
	Z       uint16
	RCODE   uint16 // Response Code
	QDCount uint16 // Question Count
	ANCount uint16 // Answer Record Count
	NSCount uint16 // Authority Record Count
	ARCount uint16 // Additional Record Count
}

// DNSQuestion represents a DNS question in the query
type DNSQuestion struct {
	Name  string
	Type  uint16
	Class uint16
}

// DNSResourceRecord represents a DNS resource record
type DNSResourceRecord struct {
	Name  string
	Type  uint16
	Class uint16
	TTL   uint32
	RDLen uint16
	RData []byte
}

// DNSQuery represents a complete DNS query
type DNSQuery struct {
	Header     DNSHeader
	Questions  []DNSQuestion
	Answers    []DNSResourceRecord
	Authority  []DNSResourceRecord
	Additional []DNSResourceRecord
}

// DNSConfig holds configuration for DNS operations
type DNSConfig struct {
	RootServers []string
	LocalDNSServer string
	InterfaceName string
	Timeout time.Duration
}

// MXRecord represents an MX (Mail Exchange) record
type MXRecord struct {
	Preference uint16
	Exchange   string
	Address    net.IP
}