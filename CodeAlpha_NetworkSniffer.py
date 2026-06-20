#!/usr/bin/env python3
"""
CodeAlpha_NetworkSniffer - Advanced Network Scanner & Packet Sniffer
No external libraries needed!
"""

import socket
import threading
import queue
import time
import sys
import re
from datetime import datetime
from ipaddress import ip_address, ip_network
import random
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import signal
import json
import os
import struct
from typing import List, Dict, Set, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
import select

# Service signatures
COMMON_SERVICES = {
    20: "FTP-data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP-Server",
    68: "DHCP-Client",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    111: "RPCbind",
    123: "NTP",
    135: "MSRPC",
    137: "NetBIOS-NS",
    138: "NetBIOS-DGM",
    139: "NetBIOS-SSN",
    143: "IMAP",
    161: "SNMP",
    162: "SNMP-Trap",
    179: "BGP",
    389: "LDAP",
    443: "HTTPS",
    445: "Microsoft-DS",
    465: "SMTPS",
    514: "Syslog",
    636: "LDAPS",
    993: "IMAPS",
    995: "POP3S",
    1080: "SOCKS",
    1433: "MSSQL",
    1521: "Oracle",
    1701: "L2TP",
    1723: "PPTP",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    27017: "MongoDB"
}

# Ethernet protocol types
ETH_P_IP = 0x0800
ETH_P_ARP = 0x0806

class PortState(Enum):
    """Enum for port states"""
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    UNKNOWN = "unknown"

class PacketType(Enum):
    """Packet types for sniffing"""
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"
    ARP = "ARP"
    IP = "IP"
    UNKNOWN = "Unknown"

@dataclass
class ScanResult:
    """Scan Result Class"""
    target: str
    port: int
    state: str
    service: Optional[str] = None
    version: Optional[str] = None
    banner: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.now)
    
    def __str__(self) -> str:
        service_str = f" [{self.service}]" if self.service else ""
        return f"{self.target}:{self.port} - {self.state}{service_str}"
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization"""
        return {
            "target": self.target,
            "port": self.port,
            "state": self.state,
            "service": self.service,
            "version": self.version,
            "banner": self.banner,
            "timestamp": self.timestamp.isoformat()
        }

@dataclass
class PacketInfo:
    """Packet information class"""
    timestamp: datetime
    source_ip: str
    dest_ip: str
    source_port: Optional[int]
    dest_port: Optional[int]
    protocol: str
    size: int
    payload: Optional[bytes] = None
    flags: Optional[str] = None
    ttl: Optional[int] = None
    
    def __str__(self) -> str:
        base = f"{self.timestamp.strftime('%H:%M:%S')} | {self.source_ip}:{self.source_port if self.source_port else '*'}"
        base += f" -> {self.dest_ip}:{self.dest_port if self.dest_port else '*'}"
        base += f" | {self.protocol} | Size: {self.size} bytes"
        if self.flags:
            base += f" | Flags: {self.flags}"
        return base

class CodeAlpha_NetworkSniffer:
    """Advanced Network Scanner and Packet Sniffer"""
    
    def __init__(self):
        # Configuration properties
        self.targets: List[str] = []
        self.ports: Set[int] = set()
        self.timeout: int = 1000  # milliseconds
        self.threads: int = 100
        self.scan_type: str = "TCP_CONNECT"
        self.service_detection: bool = True
        self.banner_grabbing: bool = True
        self.verbose: bool = False
        self.randomize_order: bool = True
        self.delay_between_probes: int = 0  # milliseconds
        self.output_file: Optional[str] = None
        self.ping_sweep: bool = False
        self.excluded_ports: List[str] = []
        self.rate_limit: int = 0
        
        # Sniffing specific
        self.sniff_interface: Optional[str] = None
        self.sniff_timeout: int = 30  # seconds
        self.max_packets: int = 100
        self.packet_count: int = 0
        self.packets: List[PacketInfo] = []
        self.sniffing: bool = False
        self.sniff_filter: Optional[str] = None  # e.g., "tcp", "udp", "icmp"
        
        # Results storage
        self.results: List[ScanResult] = []
        self.ports_scanned: int = 0
        self.scan_start_time: float = 0
        self.scan_end_time: float = 0
        self._lock = threading.Lock()
        self._stop_scan = False
        
        # Signal handling
        signal.signal(signal.SIGINT, self._signal_handler)
    
    def _signal_handler(self, sig, frame):
        """Handle Ctrl+C gracefully"""
        print("\n\n[!] Operation interrupted by user.")
        if self.sniffing:
            self.sniffing = False
        self._stop_scan = True
    
    # ==================== TARGET SETUP METHODS ====================
    
    def set_target(self, target_spec: str) -> None:
        """Set targets from specification string"""
        try:
            if ',' in target_spec:
                parts = target_spec.split(',')
                for part in parts:
                    resolved = self._resolve_hostname(part.strip())
                    if resolved:
                        self.targets.append(resolved)
            elif '-' in target_spec and not target_spec.startswith('http'):
                # IP range expansion
                self.targets.extend(self._expand_ip_range(target_spec))
            else:
                resolved = self._resolve_hostname(target_spec)
                if resolved:
                    self.targets.append(resolved)
        except Exception as e:
            print(f"Error setting target: {e}")
    
    def _expand_ip_range(self, range_str: str) -> List[str]:
        """Expand IP range like 192.168.1.1-100"""
        ips = []
        try:
            parts = range_str.split('-')
            start_ip = parts[0]
            end_ip = parts[1]
            
            start_parts = start_ip.split('.')
            end_parts = end_ip.split('.')
            
            if len(start_parts) == 4 and len(end_parts) == 4:
                start_last = int(start_parts[3])
                end_last = int(end_parts[3])
                base_ip = f"{start_parts[0]}.{start_parts[1]}.{start_parts[2]}."
                
                for i in range(start_last, end_last + 1):
                    ips.append(f"{base_ip}{i}")
        except Exception as e:
            print(f"Error expanding IP range: {e}")
        
        return ips
    
    def _resolve_hostname(self, hostname: str) -> Optional[str]:
        """Resolve hostname to IP address"""
        try:
            # Check if it's already an IP
            try:
                ip_address(hostname)
                return hostname
            except ValueError:
                pass
            
            # Try to resolve
            addr_info = socket.getaddrinfo(hostname, None, socket.AF_INET)
            if addr_info:
                return addr_info[0][4][0]
        except socket.gaierror as e:
            print(f"Cannot resolve: {hostname} - {e}")
        return None
    
    # ==================== PORT SETUP METHODS ====================
    
    def set_ports(self, port_spec: str) -> None:
        """Set ports from specification string"""
        self.ports.clear()
        
        try:
            parts = port_spec.split(',')
            
            for part in parts:
                part = part.strip()
                if '-' in part:
                    # Port range
                    range_parts = part.split('-')
                    start = int(range_parts[0])
                    end = int(range_parts[1])
                    for p in range(start, end + 1):
                        if not self._is_excluded(p):
                            self.ports.add(p)
                elif part.lower() == 'common':
                    self._add_common_ports()
                else:
                    port = int(part)
                    if not self._is_excluded(port):
                        self.ports.add(port)
            
            if not self.ports:
                self._add_common_ports()
                
        except ValueError as e:
            print(f"Error parsing ports: {e}")
            self._add_common_ports()
    
    def _add_common_ports(self) -> None:
        """Add common ports"""
        common = [21, 22, 23, 25, 53, 80, 110, 443, 3306, 3389, 5432, 5900, 8080]
        for port in common:
            if not self._is_excluded(port):
                self.ports.add(port)
    
    def _is_excluded(self, port: int) -> bool:
        """Check if port is excluded"""
        for excl in self.excluded_ports:
            if '-' in excl:
                range_parts = excl.split('-')
                start = int(range_parts[0])
                end = int(range_parts[1])
                if start <= port <= end:
                    return True
            elif int(excl) == port:
                return True
        return False
    
    def set_excluded_ports(self, port_spec: str) -> None:
        """Set excluded ports from specification"""
        parts = port_spec.split(',')
        for part in parts:
            self.excluded_ports.append(part.strip())
    
    # ==================== PORT SCANNING METHODS ====================
    
    def scan_port(self, target: str, port: int) -> Optional[ScanResult]:
        """Scan a single port"""
        if self._stop_scan:
            return None
            
        with self._lock:
            self.ports_scanned += 1
        
        try:
            # Create socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout / 1000.0)  # Convert to seconds
            
            # Connect
            start_time = time.time()
            result = sock.connect_ex((target, port))
            elapsed_time = (time.time() - start_time) * 1000  # milliseconds
            
            if result == 0:
                # Port is open
                scan_result = ScanResult(target, port, "open")
                
                if self.service_detection:
                    service = COMMON_SERVICES.get(port)
                    scan_result.service = service if service else "unknown"
                
                if self.banner_grabbing:
                    self._grab_banner(sock, scan_result)
                
                with self._lock:
                    self.results.append(scan_result)
                
                if self.verbose:
                    print(f"\n+ {scan_result}")
                else:
                    service_str = f" [{scan_result.service}]" if scan_result.service else ""
                    print(f"\r+ Found open port: {target}:{port}{service_str}")
                
                sock.close()
                return scan_result
            
            sock.close()
            return None
            
        except socket.timeout:
            if self.verbose:
                print(f"\nTimeout: {target}:{port}")
        except socket.error as e:
            if self.verbose:
                print(f"\nError: {target}:{port} - {e}")
        except Exception as e:
            if self.verbose:
                print(f"\nUnexpected error: {target}:{port} - {e}")
        
        return None
    
    def _grab_banner(self, sock: socket.socket, scan_result: ScanResult) -> None:
        """Grab banner from open port"""
        try:
            sock.settimeout(2.0)  # 2 second timeout for banner grabbing
            
            # Send a probe for common services
            probes = {
                21: "QUIT\r\n",
                22: "",  # SSH just wait for banner
                23: "",  # Telnet just wait for banner
                25: "QUIT\r\n",
                80: "HEAD / HTTP/1.0\r\n\r\n",
                443: "",  # HTTPS - just wait for banner
                3306: "",  # MySQL - just wait for banner
                8080: "HEAD / HTTP/1.0\r\n\r\n",
            }
            
            # Send probe if available
            if scan_result.port in probes and probes[scan_result.port]:
                try:
                    sock.send(probes[scan_result.port].encode())
                except:
                    pass
            
            # Read response
            banner = bytearray()
            start_time = time.time()
            
            while time.time() - start_time < 2.0:
                try:
                    data = sock.recv(1024)
                    if not data:
                        break
                    banner.extend(data)
                    if len(banner) > 200:  # Limit banner size
                        break
                except socket.timeout:
                    break
                except:
                    break
            
            banner_str = banner.decode('utf-8', errors='ignore').strip()
            if banner_str:
                # Clean up the banner
                banner_str = ' '.join(banner_str.split())
                scan_result.banner = banner_str[:200]  # Limit banner length
                
                # Extract version from banner
                version_match = re.search(r'\d+\.\d+(\.\d+)?', banner_str)
                if version_match:
                    scan_result.version = version_match.group()
                    
        except Exception as e:
            if self.verbose:
                print(f"Banner grab error on port {scan_result.port}: {e}")
    
    # ==================== PING SWEEP METHODS ====================
    
    def _is_host_alive(self, host: str) -> bool:
        """Check if host is alive using ping"""
        try:
            # Try ICMP ping using socket (works on some systems)
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
                sock.settimeout(self.timeout / 1000.0)
                
                # Create ICMP echo request packet
                packet = self._create_icmp_packet()
                start_time = time.time()
                sock.sendto(packet, (host, 0))
                
                try:
                    data, addr = sock.recvfrom(1024)
                    if time.time() - start_time < self.timeout / 1000.0:
                        sock.close()
                        return True
                except socket.timeout:
                    pass
                sock.close()
            except socket.error:
                pass
            
            # Fallback to TCP ping (connect to port 7 echo)
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1.0)
                sock.connect((host, 7))
                sock.close()
                return True
            except:
                pass
                
        except socket.error:
            # If raw socket not available, try standard connection
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout / 1000.0)
                sock.connect((host, 80))
                sock.close()
                return True
            except:
                pass
        
        return False
    
    def _create_icmp_packet(self) -> bytes:
        """Create ICMP echo request packet"""
        # ICMP Echo Request packet
        icmp_type = 8  # Echo request
        icmp_code = 0
        icmp_checksum = 0
        icmp_id = random.randint(1, 65535)
        icmp_seq = 1
        
        # Pack header without checksum
        header = struct.pack('!BBHHH', icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq)
        data = b'Hello'
        
        # Calculate checksum
        checksum = self._calculate_checksum(header + data)
        header = struct.pack('!BBHHH', icmp_type, icmp_code, checksum, icmp_id, icmp_seq)
        
        return header + data
    
    def _calculate_checksum(self, data: bytes) -> int:
        """Calculate ICMP checksum"""
        if len(data) % 2 != 0:
            data += b'\x00'
        
        words = [int.from_bytes(data[i:i+2], 'big') for i in range(0, len(data), 2)]
        checksum = sum(words)
        checksum = (checksum >> 16) + (checksum & 0xFFFF)
        checksum = ~checksum & 0xFFFF
        return checksum
    
    def perform_ping_sweep(self) -> None:
        """Perform ping sweep on targets"""
        print("\nPerforming ping sweep...")
        alive_hosts = []
        
        for host in self.targets:
            if self._is_host_alive(host):
                alive_hosts.append(host)
                print(f"  + {host} is alive")
            else:
                print(f"  - {host} is not responding")
        
        self.targets = alive_hosts
        print(f"Found {len(self.targets)} alive hosts\n")
    
    # ==================== PACKET SNIFFING METHODS ====================
    
    def _create_raw_socket(self) -> Optional[socket.socket]:
        """Create a raw socket for packet sniffing"""
        try:
            # Create raw socket
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_IP))
            sock.settimeout(1.0)  # 1 second timeout
            return sock
        except PermissionError:
            print("Permission denied. Please run with administrator/root privileges.")
            return None
        except Exception as e:
            print(f"Error creating raw socket: {e}")
            return None
    
    def _parse_ip_header(self, data: bytes) -> Tuple[dict, bytes]:
        """Parse IP header from packet data"""
        # IP header format: version/ihl, tos, total_len, id, flags/frag, ttl, protocol, checksum, src, dst
        ip_header = {}
        
        # Get first byte for version and header length
        version_ihl = data[0]
        ip_header['version'] = (version_ihl >> 4) & 0xF
        ip_header['ihl'] = version_ihl & 0xF
        ip_header['tos'] = data[1]
        ip_header['total_length'] = struct.unpack('!H', data[2:4])[0]
        ip_header['id'] = struct.unpack('!H', data[4:6])[0]
        ip_header['flags_frag'] = struct.unpack('!H', data[6:8])[0]
        ip_header['ttl'] = data[8]
        ip_header['protocol'] = data[9]
        ip_header['checksum'] = struct.unpack('!H', data[10:12])[0]
        ip_header['src_ip'] = socket.inet_ntoa(data[12:16])
        ip_header['dest_ip'] = socket.inet_ntoa(data[16:20])
        
        # Calculate header length in bytes
        ihl_bytes = ip_header['ihl'] * 4
        
        # Return payload after IP header
        payload = data[ihl_bytes:]
        
        return ip_header, payload
    
    def _parse_tcp_header(self, data: bytes) -> Tuple[dict, bytes]:
        """Parse TCP header from packet data"""
        tcp_header = {
            'src_port': struct.unpack('!H', data[0:2])[0],
            'dest_port': struct.unpack('!H', data[2:4])[0],
            'seq': struct.unpack('!I', data[4:8])[0],
            'ack': struct.unpack('!I', data[8:12])[0],
            'offset_flags': struct.unpack('!H', data[12:14])[0],
            'window': struct.unpack('!H', data[14:16])[0],
            'checksum': struct.unpack('!H', data[16:18])[0],
            'urgent': struct.unpack('!H', data[18:20])[0]
        }
        
        # Parse flags
        flags = tcp_header['offset_flags'] & 0x3F
        flags_str = ''
        if flags & 0x01: flags_str += 'F'  # FIN
        if flags & 0x02: flags_str += 'S'  # SYN
        if flags & 0x04: flags_str += 'R'  # RST
        if flags & 0x08: flags_str += 'P'  # PSH
        if flags & 0x10: flags_str += 'A'  # ACK
        if flags & 0x20: flags_str += 'U'  # URG
        tcp_header['flags'] = flags_str
        
        # Calculate header length
        header_len = (tcp_header['offset_flags'] >> 12) * 4
        payload = data[header_len:]
        
        return tcp_header, payload
    
    def _parse_udp_header(self, data: bytes) -> Tuple[dict, bytes]:
        """Parse UDP header from packet data"""
        udp_header = {
            'src_port': struct.unpack('!H', data[0:2])[0],
            'dest_port': struct.unpack('!H', data[2:4])[0],
            'length': struct.unpack('!H', data[4:6])[0],
            'checksum': struct.unpack('!H', data[6:8])[0]
        }
        
        payload = data[8:]
        return udp_header, payload
    
    def _parse_icmp_header(self, data: bytes) -> Tuple[dict, bytes]:
        """Parse ICMP header from packet data"""
        icmp_header = {
            'type': data[0],
            'code': data[1],
            'checksum': struct.unpack('!H', data[2:4])[0]
        }
        
        # ICMP types
        icmp_types = {
            0: 'Echo Reply',
            3: 'Destination Unreachable',
            5: 'Redirect',
            8: 'Echo Request',
            11: 'Time Exceeded',
            12: 'Parameter Problem'
        }
        icmp_header['description'] = icmp_types.get(icmp_header['type'], f'Type {icmp_header["type"]}')
        
        # Get rest of packet (identifier/sequence for echo, etc.)
        payload = data[4:]
        if len(payload) >= 4:
            icmp_header['id'] = struct.unpack('!H', payload[0:2])[0]
            icmp_header['seq'] = struct.unpack('!H', payload[2:4])[0]
        
        return icmp_header, payload
    
    def _parse_arp_header(self, data: bytes) -> dict:
        """Parse ARP header from packet data"""
        arp_header = {
            'hardware_type': struct.unpack('!H', data[0:2])[0],
            'protocol_type': struct.unpack('!H', data[2:4])[0],
            'hw_addr_len': data[4],
            'proto_addr_len': data[5],
            'operation': struct.unpack('!H', data[6:8])[0],
        }
        
        # ARP operation types
        arp_ops = {1: 'Request', 2: 'Reply'}
        arp_header['operation_str'] = arp_ops.get(arp_header['operation'], f'Operation {arp_header["operation"]}')
        
        # Parse sender and target addresses (assuming IPv4 and Ethernet)
        if arp_header['hw_addr_len'] == 6 and arp_header['proto_addr_len'] == 4:
            # Sender MAC
            arp_header['sender_mac'] = ':'.join(f'{b:02x}' for b in data[8:14])
            # Sender IP
            arp_header['sender_ip'] = '.'.join(str(b) for b in data[14:18])
            # Target MAC
            arp_header['target_mac'] = ':'.join(f'{b:02x}' for b in data[18:24])
            # Target IP
            arp_header['target_ip'] = '.'.join(str(b) for b in data[24:28])
        
        return arp_header
    
    def sniff_packets(self, count: int = 0, timeout: int = 30, 
                      filter_proto: Optional[str] = None) -> List[PacketInfo]:
        """
        Sniff network packets
        
        Args:
            count: Number of packets to capture (0 for unlimited)
            timeout: Timeout in seconds
            filter_proto: Filter by protocol ('tcp', 'udp', 'icmp', 'arp')
        """
        self.sniffing = True
        self.packet_count = 0
        self.packets = []
        self.max_packets = count if count > 0 else 999999
        self.sniff_timeout = timeout
        self.sniff_filter = filter_proto.lower() if filter_proto else None
        
        sock = self._create_raw_socket()
        if not sock:
            return []
        
        print(f"\n[+] Starting packet sniffing...")
        print(f"[+] Timeout: {timeout} seconds")
        if filter_proto:
            print(f"[+] Filter: {filter_proto.upper()}")
        if count > 0:
            print(f"[+] Max packets: {count}")
        print("[+] Press Ctrl+C to stop\n")
        
        start_time = time.time()
        
        try:
            while self.sniffing and self.packet_count < self.max_packets:
                if time.time() - start_time > timeout:
                    break
                
                try:
                    # Receive packet
                    data, addr = sock.recvfrom(65535)
                    
                    # Parse Ethernet header
                    eth_header = data[0:14]
                    eth_type = struct.unpack('!H', data[12:14])[0]
                    
                    if eth_type == ETH_P_IP:
                        # IP Packet
                        ip_header, payload = self._parse_ip_header(data[14:])
                        
                        # Determine protocol
                        protocol = ip_header['protocol']
                        src_ip = ip_header['src_ip']
                        dest_ip = ip_header['dest_ip']
                        ttl = ip_header['ttl']
                        
                        packet_info = None
                        
                        if protocol == 6:  # TCP
                            if self.sniff_filter and self.sniff_filter != 'tcp':
                                continue
                            tcp_header, tcp_payload = self._parse_tcp_header(payload)
                            packet_info = PacketInfo(
                                timestamp=datetime.now(),
                                source_ip=src_ip,
                                dest_ip=dest_ip,
                                source_port=tcp_header['src_port'],
                                dest_port=tcp_header['dest_port'],
                                protocol='TCP',
                                size=ip_header['total_length'],
                                payload=tcp_payload[:100],  # Limit payload size
                                flags=tcp_header.get('flags', ''),
                                ttl=ttl
                            )
                            
                        elif protocol == 17:  # UDP
                            if self.sniff_filter and self.sniff_filter != 'udp':
                                continue
                            udp_header, udp_payload = self._parse_udp_header(payload)
                            packet_info = PacketInfo(
                                timestamp=datetime.now(),
                                source_ip=src_ip,
                                dest_ip=dest_ip,
                                source_port=udp_header['src_port'],
                                dest_port=udp_header['dest_port'],
                                protocol='UDP',
                                size=ip_header['total_length'],
                                payload=udp_payload[:100],
                                ttl=ttl
                            )
                            
                        elif protocol == 1:  # ICMP
                            if self.sniff_filter and self.sniff_filter != 'icmp':
                                continue
                            icmp_header, icmp_payload = self._parse_icmp_header(payload)
                            packet_info = PacketInfo(
                                timestamp=datetime.now(),
                                source_ip=src_ip,
                                dest_ip=dest_ip,
                                source_port=None,
                                dest_port=None,
                                protocol=f'ICMP ({icmp_header.get("description", "")})',
                                size=ip_header['total_length'],
                                payload=icmp_payload[:100],
                                ttl=ttl
                            )
                        
                        elif protocol == 2:  # IGMP
                            packet_info = PacketInfo(
                                timestamp=datetime.now(),
                                source_ip=src_ip,
                                dest_ip=dest_ip,
                                source_port=None,
                                dest_port=None,
                                protocol='IGMP',
                                size=ip_header['total_length'],
                                ttl=ttl
                            )
                            
                    elif eth_type == ETH_P_ARP:
                        # ARP Packet
                        if self.sniff_filter and self.sniff_filter != 'arp':
                            continue
                        arp_header = self._parse_arp_header(data[14:])
                        
                        packet_info = PacketInfo(
                            timestamp=datetime.now(),
                            source_ip=arp_header.get('sender_ip', 'Unknown'),
                            dest_ip=arp_header.get('target_ip', 'Unknown'),
                            source_port=None,
                            dest_port=None,
                            protocol=f'ARP ({arp_header.get("operation_str", "")})',
                            size=len(data)
                        )
                    
                    if packet_info:
                        self.packets.append(packet_info)
                        self.packet_count += 1
                        
                        # Print packet info
                        print(f"[{self.packet_count}] {packet_info}")
                        
                        # Try to decode payload if it's text
                        if packet_info.payload and self.verbose:
                            try:
                                payload_str = packet_info.payload.decode('utf-8', errors='ignore').strip()
                                if payload_str and len(payload_str) > 5:
                                    print(f"    Payload: {payload_str[:100]}...")
                            except:
                                pass
                        
                        if self.packet_count >= self.max_packets:
                            break
                            
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.verbose:
                        print(f"Error processing packet: {e}")
                    continue
                    
        except KeyboardInterrupt:
            print("\n\n[!] Sniffing stopped by user")
        finally:
            self.sniffing = False
            sock.close()
        
        print(f"\n[+] Captured {len(self.packets)} packets")
        return self.packets
    
    def save_packets(self, filename: str, packets: List[PacketInfo]) -> None:
        """Save captured packets to file"""
        try:
            data = []
            for p in packets:
                data.append({
                    'timestamp': p.timestamp.isoformat(),
                    'source_ip': p.source_ip,
                    'dest_ip': p.dest_ip,
                    'source_port': p.source_port,
                    'dest_port': p.dest_port,
                    'protocol': p.protocol,
                    'size': p.size,
                    'flags': p.flags,
                    'ttl': p.ttl
                })
            
            with open(filename, 'w') as f:
                json.dump(data, f, indent=2)
            print(f"Packets saved to: {filename}")
        except Exception as e:
            print(f"Error saving packets: {e}")
    
    # ==================== MAIN SCAN METHOD ====================
    
    def scan(self) -> None:
        """Main scan method"""
        self.scan_start_time = time.time()
        
        print("\n" + "=" * 41)
        print("   CODEALPHA_NETWORKSNIFFER v1.0")
        print("   Advanced Network Scanner & Sniffer")
        print("=" * 41)
        print()
        print(f"Target(s): {self.targets}")
        print(f"Ports to scan: {len(self.ports)}")
        print(f"Threads: {self.threads}")
        print(f"Timeout: {self.timeout}ms")
        print(f"Service detection: {'ON' if self.service_detection else 'OFF'}")
        print("=" * 41 + "\n")
        
        if self.ping_sweep:
            self.perform_ping_sweep()
            if not self.targets:
                print("No alive hosts found. Exiting.")
                return
        
        # Convert ports to list and randomize if needed
        port_list = list(self.ports)
        if self.randomize_order:
            random.shuffle(port_list)
        
        total_scans = len(port_list) * len(self.targets)
        completed = 0
        open_ports_count = 0
        
        print("Scanning in progress...\n")
        
        # Use ThreadPoolExecutor for concurrent scanning
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            
            for target_host in self.targets:
                for port in port_list:
                    if self._stop_scan:
                        break
                    future = executor.submit(self.scan_port, target_host, port)
                    futures.append(future)
                    
                    # Rate limiting
                    if self.delay_between_probes > 0:
                        time.sleep(self.delay_between_probes / 1000.0)
            
            # Wait for all futures to complete
            for future in as_completed(futures):
                if self._stop_scan:
                    # Cancel remaining futures
                    for f in futures:
                        f.cancel()
                    break
                
                completed += 1
                with self._lock:
                    open_ports_count = len([r for r in self.results if r.state == "open"])
                
                if completed % 50 == 0 or completed == total_scans:
                    percent = (completed * 100) // total_scans if total_scans > 0 else 0
                    print(f"\rProgress: {percent}% ({completed}/{total_scans}) - Open ports: {open_ports_count}", end='')
                    sys.stdout.flush()
        
        self.scan_end_time = time.time()
        print("\n")
        
        # Generate report
        self.generate_report()
    
    # ==================== REPORT GENERATION ====================
    
    def generate_report(self) -> None:
        """Generate scan report"""
        duration = (self.scan_end_time - self.scan_start_time) * 1000  # milliseconds
        
        print("=" * 41)
        print("           SCAN COMPLETE")
        print("=" * 41)
        print()
        print("Scan Statistics:")
        print(f"  - Duration: {duration:.0f} ms ({duration/1000:.1f} seconds)")
        print(f"  - Targets scanned: {len(self.targets)}")
        print(f"  - Ports scanned: {self.ports_scanned}")
        print(f"  - Open ports found: {len([r for r in self.results if r.state == 'open'])}")
        print()
        
        # Group results by target
        open_ports = [r for r in self.results if r.state == "open"]
        
        if open_ports:
            print("OPEN PORTS:")
            print("-" * 45)
            
            by_target = {}
            for result in open_ports:
                if result.target not in by_target:
                    by_target[result.target] = []
                by_target[result.target].append(result)
            
            for target, results in by_target.items():
                print(f"\nTarget: {target}")
                print("   Port  | Service      | Version")
                print("   ------+--------------+---------")
                
                for result in sorted(results, key=lambda x: x.port):
                    service = result.service if result.service else "unknown"
                    version = result.version if result.version else "-"
                    print(f"   {result.port:5d} | {service:12s} | {version}")
                    
                    if result.banner and self.verbose:
                        print(f"         Banner: {result.banner}")
            print()
        else:
            print("No open ports found.\n")
        
        if self.output_file:
            self.save_to_file(open_ports)
    
    def save_to_file(self, open_ports: List[ScanResult]) -> None:
        """Save results to file"""
        try:
            if self.output_file.endswith('.json'):
                # JSON format
                data = {
                    "date": datetime.now().isoformat(),
                    "targets": self.targets,
                    "open_ports": [r.to_dict() for r in open_ports],
                    "statistics": {
                        "total_ports_scanned": self.ports_scanned,
                        "total_targets": len(self.targets),
                        "duration_ms": (self.scan_end_time - self.scan_start_time) * 1000
                    }
                }
                with open(self.output_file, 'w') as f:
                    json.dump(data, f, indent=2)
            else:
                # Text format
                with open(self.output_file, 'w') as f:
                    f.write("PORT SCAN RESULTS\n")
                    f.write("=================\n")
                    f.write(f"Date: {datetime.now()}\n")
                    f.write(f"Targets: {self.targets}\n")
                    f.write(f"Open ports found: {len(open_ports)}\n\n")
                    
                    for result in open_ports:
                        f.write(f"{result.target}:{result.port} - {result.state}")
                        if result.service:
                            f.write(f" [{result.service}]")
                        if result.version:
                            f.write(f" {result.version}")
                        f.write("\n")
                        if result.banner:
                            f.write(f"  Banner: {result.banner}\n")
            
            print(f"Results saved to: {self.output_file}")
        except Exception as e:
            print(f"Error saving results: {e}")


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='CodeAlpha_NetworkSniffer - Advanced Network Scanner & Packet Sniffer',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Port Scanning
  python CodeAlpha_NetworkSniffer.py -t localhost -p common
  python CodeAlpha_NetworkSniffer.py -t 127.0.0.1 -p 80,443,22 -v
  python CodeAlpha_NetworkSniffer.py -t google.com -p 1-100 --threads 200
  
  # Packet Sniffing
  python CodeAlpha_NetworkSniffer.py --sniff --count 10
  python CodeAlpha_NetworkSniffer.py --sniff --filter tcp --verbose
  python CodeAlpha_NetworkSniffer.py --sniff --filter arp --save-packets packets.json
  
  # Combined
  python CodeAlpha_NetworkSniffer.py -t scanme.nmap.org -p 1-1000 --output results.txt
        '''
    )
    
    # Port scanning arguments
    parser.add_argument('-t', '--target', 
                       help='IP, hostname, or range (192.168.1.1-100)')
    parser.add_argument('-p', '--ports', 
                       help='Ports: 80,443, 1-1000, or "common"')
    parser.add_argument('--threads', type=int, default=100,
                       help='Number of threads (default: 100)')
    parser.add_argument('--timeout', type=int, default=1000,
                       help='Connection timeout in milliseconds (default: 1000)')
    parser.add_argument('--delay', type=int, default=0,
                       help='Delay between probes in milliseconds (stealth)')
    parser.add_argument('--output', 
                       help='Save results to file (.txt or .json)')
    parser.add_argument('--exclude', 
                       help='Exclude ports (22,3389, 5900-6000)')
    parser.add_argument('--ping-sweep', action='store_true',
                       help='Check if hosts are alive first')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Show detailed output')
    parser.add_argument('--no-service', action='store_true',
                       help='Disable service detection')
    parser.add_argument('--no-banner', action='store_true',
                       help='Disable banner grabbing')
    parser.add_argument('--no-random', action='store_true',
                       help='Disable randomizing port order')
    
    # Packet sniffing arguments
    parser.add_argument('--sniff', action='store_true',
                       help='Enable packet sniffing mode')
    parser.add_argument('--count', type=int, default=0,
                       help='Number of packets to capture (0 for unlimited)')
    parser.add_argument('--sniff-timeout', type=int, default=30,
                       help='Sniffing timeout in seconds (default: 30)')
    parser.add_argument('--filter', choices=['tcp', 'udp', 'icmp', 'arp'],
                       help='Filter packets by protocol')
    parser.add_argument('--save-packets', 
                       help='Save captured packets to file (JSON)')
    
    return parser.parse_args()


def main():
    """Main entry point"""
    args = parse_arguments()
    
    # Check if sniffing mode is enabled
    if args.sniff:
        # Packet sniffing mode
        sniffer = CodeAlpha_NetworkSniffer()
        sniffer.verbose = args.verbose
        
        # Sniff packets
        packets = sniffer.sniff_packets(
            count=args.count,
            timeout=args.sniff_timeout,
            filter_proto=args.filter
        )
        
        # Save packets if requested
        if args.save_packets and packets:
            sniffer.save_packets(args.save_packets, packets)
        
        return
    
    # Port scanning mode (original functionality)
    if not args.target:
        print("Error: No target specified. Use -t <target> or use --sniff for packet sniffing")
        sys.exit(1)
    
    # Create scanner instance
    scanner = CodeAlpha_NetworkSniffer()
    
    # Configure scanner
    scanner.threads = args.threads
    scanner.timeout = args.timeout
    scanner.delay_between_probes = args.delay
    scanner.output_file = args.output
    scanner.ping_sweep = args.ping_sweep
    scanner.verbose = args.verbose
    scanner.service_detection = not args.no_service
    scanner.banner_grabbing = not args.no_banner
    scanner.randomize_order = not args.no_random
    
    # Set target and ports
    scanner.set_target(args.target)
    if args.ports:
        scanner.set_ports(args.ports)
    else:
        # Default to common ports if not specified
        scanner.set_ports("common")
    
    if args.exclude:
        scanner.set_excluded_ports(args.exclude)
    
    # Run scan
    try:
        scanner.scan()
    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user")
        scanner.generate_report()
    except Exception as e:
        print(f"\n[!] Error during scan: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()