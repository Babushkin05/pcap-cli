package core

import (
	"net/netip"
	"time"
)

type ARPCorrelator struct {
	window  time.Duration
	pending map[ARPKey]time.Time
	matched int
}

func NewARPCorrelator(window time.Duration) *ARPCorrelator {
	if window <= 0 {
		window = 3 * time.Second
	}
	return &ARPCorrelator{
		window:  window,
		pending: make(map[ARPKey]time.Time),
	}
}

func (c *ARPCorrelator) OnARP(e ARPEvent) {
	switch e.Op {
	case ARPOpRequest:
		if k, ok := KeyFromRequest(e); ok {
			c.pending[k] = e.Timestamp
		}
	case ARPOpReply:
		if k, ok := KeyFromReplyAsRequestKey(e); ok {
			if tReq, exists := c.pending[k]; exists {
				// match only if reply arrived within the window
				if !e.Timestamp.IsZero() && !tReq.IsZero() && e.Timestamp.Sub(tReq) <= c.window {
					c.matched++
					delete(c.pending, k)
				}
			}
		}
	}
}

func (c *ARPCorrelator) Cleanup(now time.Time) {
	// remove old pending to prevent map growth
	for k, t := range c.pending {
		if !t.IsZero() && now.Sub(t) > c.window {
			delete(c.pending, k)
		}
	}
}

func (c *ARPCorrelator) MatchedPairs() int { return c.matched }

func (c *ARPCorrelator) PendingCount() int { return len(c.pending) }

// чтобы не ругался импорт netip
var _ = netip.Addr{}
