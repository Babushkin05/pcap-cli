package core

import (
	"fmt"
	"net"
	"net/netip"
	"time"
)

type ARPEvent struct {
	Timestamp time.Time

	// Ethernet header
	SrcMAC net.HardwareAddr
	DstMAC net.HardwareAddr

	// ARP
	Op uint16

	SenderMAC net.HardwareAddr
	SenderIP  netip.Addr

	TargetMAC net.HardwareAddr
	TargetIP  netip.Addr
}

func IsBroadcastMAC(mac net.HardwareAddr) bool {
	return len(mac) == 6 &&
		mac[0] == 0xff && mac[1] == 0xff && mac[2] == 0xff &&
		mac[3] == 0xff && mac[4] == 0xff && mac[5] == 0xff
}

func IsGratuitousARPRequest(e ARPEvent) bool {
	return e.Op == ARPOpRequest && e.SenderIP.IsValid() && e.SenderIP == e.TargetIP
}

func DescribeARP(e ARPEvent) string {
	ts := e.Timestamp
	if ts.IsZero() {
		// time metadata did not arrive
		ts = time.Now()
	}

	switch e.Op {
	case ARPOpRequest:
		// who-has TPA tell SPA
		return fmt.Sprintf("%s ARP who-has %s tell %s | eth %s -> %s | sha=%s tha=%s",
			ts.Format(time.RFC3339Nano),
			e.TargetIP, e.SenderIP,
			e.SrcMAC, e.DstMAC,
			e.SenderMAC, e.TargetMAC,
		)
	case ARPOpReply:
		// SPA is-at SHA (to TPA)
		return fmt.Sprintf("%s ARP reply %s is-at %s (to %s) | eth %s -> %s",
			ts.Format(time.RFC3339Nano),
			e.SenderIP, e.SenderMAC, e.TargetIP,
			e.SrcMAC, e.DstMAC,
		)
	default:
		return fmt.Sprintf("%s ARP op=%d %s(%s) -> %s(%s) | eth %s -> %s",
			ts.Format(time.RFC3339Nano),
			e.Op,
			e.SenderIP, e.SenderMAC,
			e.TargetIP, e.TargetMAC,
			e.SrcMAC, e.DstMAC,
		)
	}
}

// Key for correlation of request/response.
type ARPKey struct {
	Requester netip.Addr // SPA request
	Target    netip.Addr // TPA request
}

func KeyFromRequest(e ARPEvent) (ARPKey, bool) {
	if e.Op != ARPOpRequest || !e.SenderIP.IsValid() || !e.TargetIP.IsValid() {
		return ARPKey{}, false
	}
	return ARPKey{Requester: e.SenderIP, Target: e.TargetIP}, true
}

func KeyFromReplyAsRequestKey(e ARPEvent) (ARPKey, bool) {
	// Reply: SPA = who was asked; TPA = who asked
	if e.Op != ARPOpReply || !e.SenderIP.IsValid() || !e.TargetIP.IsValid() {
		return ARPKey{}, false
	}
	return ARPKey{Requester: e.TargetIP, Target: e.SenderIP}, true
}
