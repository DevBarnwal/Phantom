#!/usr/bin/env python3
"""
packet_analyzer.py
Packet analysis and processing utilities.
"""

import time
import logging
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.layers.dns import DNS
from scapy.packet import Raw
from scapy.layers.http import HTTPRequest, HTTPResponse

logger = logging.getLogger(__name__)

class PacketAnalyzer:
    """Handles packet analysis and protocol identification."""
    
    @staticmethod
    def identify_protocol(packet):
        """
        Identify the protocol of a packet.
        
        Args:
            packet: Scapy packet object
            
        Returns:
            str: Protocol name (TCP, UDP, ICMP, HTTP, HTTPS, DNS, ARP, OTHER)
        """
        try:
            # Check for ARP
            if packet.haslayer(ARP):
                return "ARP"
            
            # Check for DNS
            if packet.haslayer(DNS):
                return "DNS"
            
            # Check for HTTP/HTTPS
            if packet.haslayer(TCP):
                # Check for HTTP
                if packet.haslayer(HTTPRequest) or packet.haslayer(HTTPResponse):
                    return "HTTP"
                
                # Check common HTTP ports and content
                if hasattr(packet[TCP], 'dport') and packet[TCP].dport in [80, 8080]:
                    if packet.haslayer(Raw):
                        payload = bytes(packet[Raw].load)
                        if (payload.startswith(b"GET") or payload.startswith(b"POST") or
                            payload.startswith(b"HTTP/") or b"Host:" in payload):
                            return "HTTP"
                
                # Check for HTTPS (port 443)
                if hasattr(packet[TCP], 'dport') and packet[TCP].dport == 443:
                    return "HTTPS"
                if hasattr(packet[TCP], 'sport') and packet[TCP].sport == 443:
                    return "HTTPS"
                
                return "TCP"
            
            if packet.haslayer(UDP):
                return "UDP"
            
            if packet.haslayer(ICMP):
                return "ICMP"
            
            return "OTHER"
            
        except Exception as e:
            logger.warning(f"Error identifying protocol: {e}")
            return "OTHER"
    
    @staticmethod
    def extract_packet_info(packet):
        """
        Extract basic information from a packet.
        
        Args:
            packet: Scapy packet object
            
        Returns:
            dict: Packet information
        """
        try:
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            
            # Extract source and destination
            src = ""
            dst = ""
            info = ""
            
            if packet.haslayer(IP):
                src = packet[IP].src
                dst = packet[IP].dst
            elif packet.haslayer(IPv6):
                src = packet[IPv6].src
                dst = packet[IPv6].dst
            elif packet.haslayer(ARP):
                src = packet[ARP].psrc
                dst = packet[ARP].pdst
                info = f"Who has {dst}? Tell {src}"
            elif packet.haslayer(Ether):
                src = packet[Ether].src
                dst = packet[Ether].dst
            
            protocol = PacketAnalyzer.identify_protocol(packet)
            length = len(packet)
            
            # Add protocol-specific info
            if not info:
                info = PacketAnalyzer._get_protocol_info(packet, protocol)
            
            return {
                "timestamp": timestamp,
                "src": src,
                "dst": dst,
                "protocol": protocol,
                "length": length,
                "info": info,
                "packet": packet
            }
            
        except Exception as e:
            logger.warning(f"Error extracting packet info: {e}")
            return None
    
    @staticmethod
    def _get_protocol_info(packet, protocol):
        """Get protocol-specific information."""
        try:
            if protocol == "TCP" and packet.haslayer(TCP):
                flags = []
                tcp_layer = packet[TCP]
                if tcp_layer.flags.S: flags.append("SYN")
                if tcp_layer.flags.A: flags.append("ACK")
                if tcp_layer.flags.F: flags.append("FIN")
                if tcp_layer.flags.R: flags.append("RST")
                if tcp_layer.flags.P: flags.append("PSH")
                if tcp_layer.flags.U: flags.append("URG")
                
                flag_str = ",".join(flags) if flags else "None"
                return f"Flags: {flag_str}, Seq: {tcp_layer.seq}"
            
            elif protocol == "UDP" and packet.haslayer(UDP):
                return f"Len: {packet[UDP].len}"
            
            elif protocol == "ICMP" and packet.haslayer(ICMP):
                return f"Type: {packet[ICMP].type}, Code: {packet[ICMP].code}"
            
            elif protocol == "DNS" and packet.haslayer(DNS):
                dns = packet[DNS]
                if dns.qr == 0:  # Query
                    return f"Query: {dns.qd.qname.decode() if dns.qd else 'Unknown'}"
                else:  # Response
                    return f"Response: {dns.an.rdata if dns.an else 'No answer'}"
            
            elif protocol in ["HTTP", "HTTPS"]:
                if packet.haslayer(Raw):
                    payload = packet[Raw].load.decode('utf-8', errors='ignore')
                    if payload.startswith(('GET', 'POST', 'PUT', 'DELETE')):
                        lines = payload.split('\n')
                        if lines:
                            return lines[0].strip()
                return f"{protocol} Traffic"
            
            return ""
            
        except Exception as e:
            logger.warning(f"Error getting protocol info: {e}")
            return ""
    
    @staticmethod
    def matches_filter(packet_info, filter_type):
        """
        Check if packet matches the given filter.
        
        Args:
            packet_info: Dictionary with packet information
            filter_type: String filter type
            
        Returns:
            bool: True if packet matches filter
        """
        if filter_type == "ALL":
            return True
        
        return packet_info.get("protocol", "OTHER") == filter_type