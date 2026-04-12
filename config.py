#!/usr/bin/env python3
"""
config.py
Configuration constants and settings for the packet sniffer.
"""

# GUI Configuration
DEFAULT_WINDOW_SIZE = "1000x600"
DEFAULT_WINDOW_MIN_SIZE = (800, 500)
PACKET_QUEUE_UPDATE_INTERVAL = 100  # milliseconds
THREAD_JOIN_TIMEOUT = 2.0  # seconds

# Packet Display Configuration
MAX_DISPLAYED_PACKETS = 10000  # Limit to prevent memory issues
PACKET_DISPLAY_COLUMNS = {
    "time": {"width": 160, "anchor": "w"},
    "src": {"width": 180, "anchor": "w"},
    "dst": {"width": 180, "anchor": "w"},
    "proto": {"width": 80, "anchor": "center"},
    "len": {"width": 80, "anchor": "center"},
    "info": {"width": 200, "anchor": "w"}
}

# Protocol Filters
PROTOCOL_FILTERS = {
    "ALL": "",
    "TCP": "tcp",
    "UDP": "udp", 
    "ICMP": "icmp",
    "HTTP": "",  # Custom filter applied in processing
    "HTTPS": "",  # Custom filter applied in processing
    "DNS": "port 53",
    "ARP": "arp"
}

# File Extensions
SUPPORTED_FILE_TYPES = [
    ("PCAP files", "*.pcap"),
    ("All files", "*.*")
]

# Logging Configuration
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
LOG_LEVEL = "INFO"