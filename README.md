# Network Packet Sniffer

A Python standard-library project from the CodeAlpha cybersecurity internship. The live capture path uses Linux packet sockets to read IPv4 traffic and summarize TCP, UDP, and ICMP headers.

## Implementation

[CodeAlpha_NetworkSniffer.py](CodeAlpha_NetworkSniffer.py) contains the packet parser, protocol filters, service checks, and JSON export. Live capture requires Linux and permission to open a raw packet socket. The capture socket selects IPv4 frames, so ARP traffic is outside the live capture path.

## Output

The terminal displays packet summaries. JSON export preserves structured records for later inspection. Captures and reports belong in local working directories.
