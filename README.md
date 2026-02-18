# autopath-xv

Advanced network path discovery tool that combines Layer 3 traceroute with Layer 2 MAC-level path tracing.

## Features

- **Layer 3 Traceroute**: Traditional ICMP-based traceroute functionality with TTL incrementation
- **Layer 2 Discovery**: MAC address resolution via ARP at each hop
- **Smart Mode**: Query router ARP tables via SNMP when hops become unreachable
- **Broadcast Support**: Send ARP requests to broadcast MAC address
- **Debug Mode**: Detailed packet-level debugging information
- **Route Analysis**: Detect invalid routes, missing routes, and routing inconsistencies

## Installation

### From Source

```bash
make
sudo make install
```

### Building .deb Package

```bash
# Install build dependencies
sudo apt-get install build-essential debhelper devscripts

# Build the package
make deb

# Install the package
sudo dpkg -i ../autopath-xv_1.0.0-1_*.deb
```

### Manual Installation

```bash
gcc -Wall -O2 -o autopath-xv main.c netutils.c traceroute.c
sudo cp autopath-xv /usr/local/bin/
sudo setcap cap_net_raw+ep /usr/local/bin/autopath-xv
```

## Usage

```bash
autopath-xv [OPTIONS] -ipv4 <target_ip>
```

### Options

- `-ipv4 <ip>` - Target IPv4 address (REQUIRED)
- `-a` - Use ARP for Layer 2 MAC resolution
- `-l2` - Enable Layer 2 probing
- `-b` - Use broadcast for ARP requests
- `-xv` - Smart advanced mode (query router ARP tables)
- `-d` - Enable debug output
- `-i <iface>` - Network interface to use (default: eth0)
- `--help, -help` - Display help message
- `--version` - Display version information

### Examples

Basic traceroute:
```bash
autopath-xv -ipv4 8.8.8.8
```

Traceroute with Layer 2 MAC discovery:
```bash
autopath-xv -a -l2 -ipv4 10.0.0.1
```

Full featured mode with debug:
```bash
autopath-xv -a -d -b -xv -l2 -ipv4 192.168.1.1
```

Using a specific interface:
```bash
autopath-xv -i wlan0 -a -l2 -ipv4 10.0.0.1
```

## Requirements

- Linux operating system
- Root privileges or `CAP_NET_RAW` capability
- GCC compiler (for building from source)
- Optional: SNMP for smart mode features

## Dependencies

### Runtime
- `libcap2-bin` (recommended) - For setting capabilities
- `snmp` (optional) - For smart mode router queries

### Build
- `gcc`
- `make`
- `debhelper` (for .deb packaging)

## How It Works

1. **Layer 3 Discovery**: Sends ICMP Echo Request packets with incrementing TTL values
2. **Hop Detection**: Receives ICMP Time Exceeded messages from intermediate routers
3. **Layer 2 Resolution**: Optionally sends ARP requests to resolve MAC addresses at each hop
4. **Smart Mode**: When a hop fails, queries the last reachable router's ARP table via SNMP

## Permissions

The tool requires raw socket access. You can either:

1. Run with sudo:
   ```bash
   sudo autopath-xv -ipv4 8.8.8.8
   ```

2. Grant CAP_NET_RAW capability (recommended):
   ```bash
   sudo setcap cap_net_raw+ep /usr/local/bin/autopath-xv
   autopath-xv -ipv4 8.8.8.8
   ```

## Output Format

```
Traceroute to 8.8.8.8, max 30 hops:
 1  192.168.1.1 [aa:bb:cc:dd:ee:ff]  1.23 ms
 2  10.0.0.1 [11:22:33:44:55:66]  5.67 ms
 3  172.16.1.1  12.34 ms
 ...
```

## Troubleshooting

**Permission denied error:**
- Run with `sudo` or set `CAP_NET_RAW` capability

**No MAC addresses shown:**
- Enable Layer 2 mode with `-l2 -a`
- Ensure targets are on local network for L2 visibility

**Smart mode not working:**
- Ensure SNMP is installed and routers support SNMP queries
- Check router SNMP community strings

## License

GPL v3 - See LICENSE file for details

## Author

Created for advanced network troubleshooting and path analysis.

## Contributing

Contributions are welcome! Please submit issues and pull requests on GitHub.
