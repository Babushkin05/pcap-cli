package core

import (
	"fmt"
	"time"

	"github.com/google/gopacket/pcap"
)

type CaptureOptions struct {
	Iface      string
	SnapLen    int
	Promisc    bool
	Timeout    time.Duration // pcap timeout; for reading often 500ms..2s or BlockForever
	BufferSize int           // 0 = don't touch
}

func OpenPcapHandle(opts CaptureOptions) (*pcap.Handle, error) {
	if opts.Iface == "" {
		return nil, fmt.Errorf("pcap: iface is required")
	}
	if opts.SnapLen <= 0 {
		opts.SnapLen = 65535
	}

	inactive, err := pcap.NewInactiveHandle(opts.Iface)
	if err != nil {
		return nil, fmt.Errorf("pcap: NewInactiveHandle(%q): %w", opts.Iface, err)
	}
	defer inactive.CleanUp()

	if err := inactive.SetSnapLen(opts.SnapLen); err != nil {
		return nil, fmt.Errorf("pcap: SetSnapLen: %w", err)
	}
	if err := inactive.SetPromisc(opts.Promisc); err != nil {
		return nil, fmt.Errorf("pcap: SetPromisc: %w", err)
	}
	if opts.Timeout > 0 {
		if err := inactive.SetTimeout(opts.Timeout); err != nil {
			return nil, fmt.Errorf("pcap: SetTimeout: %w", err)
		}
	}
	if opts.BufferSize > 0 {
		if err := inactive.SetBufferSize(opts.BufferSize); err != nil {
			return nil, fmt.Errorf("pcap: SetBufferSize: %w", err)
		}
	}

	h, err := inactive.Activate()
	if err != nil {
		return nil, fmt.Errorf("pcap: Activate: %w", err)
	}
	return h, nil
}

func SetBPF(h *pcap.Handle, expr string) error {
	if expr == "" {
		return nil
	}
	if err := h.SetBPFFilter(expr); err != nil {
		return fmt.Errorf("pcap: set bpf %q: %w", expr, err)
	}
	return nil
}
