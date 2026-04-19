# pcap-cli

`pcap-cli` is a small command-line tool for capturing and analyzing network traffic using PCAP.
It provides commands to sniff packets, print capture statistics, resolve the router (gateway) MAC address, and now also includes DNS analysis capabilities (HW3 extension).
Depending on your platform/network setup.

## How to build

### Requirements
- Go 1.25
- libpcap / Npcap (depending on OS) if your capture backend requires it
- Permissions to capture packets:
  - Linux: usually run with `sudo` or grant capabilities to the binary
  - macOS: usually run with `sudo`
  - Windows: Npcap installed, run terminal as Administrator if needed

### Build with Makefile
Build for your current OS:
```bash
make deps
make build
```

The binary will be created here:
```bash
./build/pcap-cli
```

Clean build artifacts:
```bash
make clean
```

Build for multiple platforms:
```bash
make build-all
```

### Build with Go directly
```bash
go build -o build/pcap-cli ./cmd
```

## How to use

### Configuration
The tool can use a YAML config file.

- Example config: `config/example.yaml`

### Run
From the project root:

```bash
./build/pcap-cli --help
```

If packet capture requires elevated privileges:

```bash
sudo ./build/pcap-cli --help
```

### Commands
The CLI is organized into subcommands (see `./cmd/*.go`). Available commands include:

#### Original Commands
- **sniff**: capture ARP packets on an interface and print them
- **stats**: show capture statistics for Ethernet/ARP traffic
- **router-mac**: resolve the router/gateway MAC address

#### New DNS Commands (HW3 Extension)
- **dns-sniff**: capture and display all DNS packets on the network
- **dns-lookup**: lookup DNS records for a domain (currently supports MX records)
- **dns-root**: query root DNS servers and compare with local DNS resolver

To see available commands and flags:
```bash
./build/pcap-cli --help
./build/pcap-cli <command> --help
```

### Notes
- Capturing traffic often requires root/administrator privileges.
- Make sure you select the correct network interface in your config (or via flags, if supported).
- If you are on Windows, ensure Npcap is installed and accessible.

## Examples

### router-mac

```
vladimir-babushkin pcap-cli % sudo ./build/pcap-cli router-mac --config cfg.yaml
Password:
11:22:33:44:55:66
```

### stats

```
vladimir-babushkin pcap-cli % sudo ./build/pcap-cli stats --config cfg.yaml
Interval: 2026-03-01T17:18:12+03:00 .. 2026-03-01T17:18:42+03:00
Ethernet frames: 10601
ARP packets: 2
Unique MACs: 5
Broadcast Ethernet: 4
Broadcast ARP: 1
Gratuitous ARP requests: 0
ARP request/reply pairs matched: 0
Bytes between me and router: 7031365
pcap drops: 0
```

### sniff

```
vladimir-babushkin pcap-cli % sudo ./build/pcap-cli sniff --config cfg.yaml
2026-03-01T17:03:27.912297+03:00 ARP reply 192.168.0.1 is-at 11:22:33:44:55:66 (to 192.168.0.10) | eth 11:22:33:44:55:66 -> aa:bb:cc:dd:ee:ff
2026-03-01T17:03:46.334229+03:00 ARP who-has 192.168.0.30 tell 192.168.0.1 | eth 11:22:33:44:55:66 -> ff:ff:ff:ff:ff:ff | sha=11:22:33:44:55:66 tha=00:00:00:00:00:00
2026-03-01T17:03:47.358194+03:00 ARP who-has 192.168.0.30 tell 192.168.0.1 | eth 11:22:33:44:55:66 -> ff:ff:ff:ff:ff:ff | sha=11:22:33:44:55:66 tha=00:00:00:00:00:00
```

### DNS Commands (HW3 Extension)

#### DNS Sniffing
```
sudo ./build/pcap-cli dns-sniff --config cfg.yaml
```

#### DNS Lookup (MX Records)
```
sudo ./build/pcap-cli dns-lookup example.com --config cfg.yaml
sudo ./build/pcap-cli dns-lookup example.com -t MX --config cfg.yaml
```

#### Root DNS Queries
```
sudo ./build/pcap-cli dns-root github.com --config cfg.yaml
sudo ./build/pcap-cli dns-root hse.ru --config cfg.yaml
sudo ./build/pcap-cli dns-root draw.io --config cfg.yaml
```