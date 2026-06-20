# CodeAlpha - Network Packet Sniffer

## Task 1: Basic Network Sniffer

### Language: Python (No external libraries needed!)

### Description
An advanced network packet sniffer and scanner built entirely with Python's standard library. Captures and analyzes network traffic in real-time.

### Features
- **Packet Sniffing**: Capture TCP, UDP, ICMP, and ARP packets
- **Protocol Analysis**: Parse IP, TCP, UDP, ICMP, and ARP headers
- **Filtering**: Filter by protocol (TCP, UDP, ICMP, ARP)
- **Port Scanning**: Scan for open ports on targets
- **Service Detection**: Identify services running on open ports
- **Banner Grabbing**: Capture service banners
- **JSON Reports**: Export results and captured packets

### Requirements
- Python 3.6+
- Administrator/root privileges (for packet sniffing)

### How to Use

#### Packet Sniffing Mode:
```bash
# Capture all packets (admin/root required)
python CodeAlpha_NetworkSniffer.py --sniff

# Capture 10 packets
python CodeAlpha_NetworkSniffer.py --sniff --count 10

# Filter by protocol
python CodeAlpha_NetworkSniffer.py --sniff --filter tcp
python CodeAlpha_NetworkSniffer.py --sniff --filter udp
python CodeAlpha_NetworkSniffer.py --sniff --filter icmp

# Save captured packets
python CodeAlpha_NetworkSniffer.py --sniff --save-packets packets.json --verbose
