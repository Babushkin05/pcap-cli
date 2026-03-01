package main

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"

	"gopkg.in/yaml.v2"
)

type Config struct {
	Iface     string
	MyIP      netip.Addr
	MyMAC     net.HardwareAddr
	RouterMAC net.HardwareAddr
	GatewayIP netip.Addr // optional
}

func LoadConfig(path string) (Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c Config) Validate() error {
	if c.Iface == "" {
		return errors.New("config: iface is required")
	}
	if !c.MyIP.IsValid() {
		return errors.New("config: my_ip is required")
	}
	if !c.MyIP.Is4() {
		return errors.New("config: my_ip must be IPv4")
	}
	if len(c.MyMAC) != 6 {
		return errors.New("config: my_mac must be 6 bytes")
	}
	if len(c.RouterMAC) != 0 && len(c.RouterMAC) != 6 {
		return errors.New("config: router_mac must be 6 bytes")
	}
	if c.GatewayIP.IsValid() && !c.GatewayIP.Is4() {
		return errors.New("config: gateway_ip must be IPv4")
	}
	return nil
}

func parseIPv4(s string) (netip.Addr, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return netip.Addr{}, errors.New("empty")
	}
	ip, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, err
	}
	if !ip.Is4() {
		return netip.Addr{}, errors.New("not an IPv4 address")
	}
	return ip, nil
}

func parseMAC(s string) (net.HardwareAddr, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	mac, err := net.ParseMAC(s)
	if err != nil {
		return nil, err
	}
	if len(mac) != 6 {
		return nil, errors.New("not a 6-byte MAC")
	}
	return mac, nil
}
func (c *Config) UnmarshalYAML(unmarshal func(any) error) error {
	type rawConfig struct {
		Iface     string `yaml:"iface"`
		MyIP      string `yaml:"my_ip"`
		MyMAC     string `yaml:"my_mac"`
		RouterMAC string `yaml:"router_mac"`
		GatewayIP string `yaml:"gateway_ip,omitempty"`
	}

	var rc rawConfig
	if err := unmarshal(&rc); err != nil {
		return fmt.Errorf("parse yaml: %w", err)
	}

	cfg := Config{}

	cfg.Iface = strings.TrimSpace(rc.Iface)
	if cfg.Iface == "" {
		return errors.New("config: iface is required")
	}

	ip, err := parseIPv4(rc.MyIP)
	if err != nil {
		return fmt.Errorf("config: my_ip: %w", err)
	}
	cfg.MyIP = ip

	mac, err := parseMAC(rc.MyMAC)
	if err != nil {
		return fmt.Errorf("config: my_mac: %w", err)
	}
	cfg.MyMAC = mac

	routerMAC, err := parseMAC(rc.RouterMAC)
	if err != nil {
		return fmt.Errorf("config: router_mac: %w", err)
	}
	cfg.RouterMAC = routerMAC

	if strings.TrimSpace(rc.GatewayIP) != "" {
		gw, err := parseIPv4(rc.GatewayIP)
		if err != nil {
			return fmt.Errorf("config: gateway_ip: %w", err)
		}
		cfg.GatewayIP = gw
	}

	if err := cfg.Validate(); err != nil {
		return err
	}

	*c = cfg
	return nil
}
