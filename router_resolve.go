package main

import (
	"context"
	"fmt"
	"net"
	"time"
)

type RouterResolveParams struct {
	// Настройки pcap/тайминги
	SnapLen     int
	Promisc     bool
	ReadTimeout time.Duration
	WaitPerTry  time.Duration
	Retries     int
}

// ResolveRouterMACFromConfig:
// - требует, чтобы в cfg был задан GatewayIP
// - отправляет ARP request и ждёт reply
// - возвращает MAC роутера
func ResolveRouterMACFromConfig(ctx context.Context, cfg Config, p RouterResolveParams) (net.HardwareAddr, error) {
	if cfg.RouterMAC != nil {
		return cfg.RouterMAC, nil
	}

	if !cfg.GatewayIP.IsValid() {
		return nil, fmt.Errorf("router-mac: gateway_ip is not set in config (required to resolve router MAC)")
	}

	return ResolveMACByARP(ctx, ResolveOptions{
		Iface:       cfg.Iface,
		SnapLen:     p.SnapLen,
		Promisc:     p.Promisc,
		ReadTimeout: p.ReadTimeout,
		WaitPerTry:  p.WaitPerTry,
		Retries:     p.Retries,
	}, cfg.MyIP, cfg.MyMAC, cfg.GatewayIP)
}
