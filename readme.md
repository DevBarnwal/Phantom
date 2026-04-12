# Advanced Packet Sniffer & Analyzer

A professional packet capture and analysis tool built with Python, Scapy, and Tkinter. This application provides a user-friendly GUI for network packet monitoring, analysis, and export capabilities.

## Features

### Core Functionality
- **Real-time packet capture** from network interfaces
- **Protocol identification** (TCP, UDP, ICMP, HTTP, HTTPS, DNS, ARP)
- **Flexible filtering** options for different protocols
- **Packet export** to PCAP format for analysis in other tools
- **Multi-threaded architecture** for responsive GUI

### Advanced Features
- **Detailed packet analysis** with protocol-specific information
- **Memory management** to prevent excessive resource usage
- **Comprehensive logging** system
- **Cross-platform compatibility** (Windows, Linux, macOS)
- **Privilege checking** for proper network access

### User Interface
- **Modern GUI** with organized layout
- **Real-time packet display** with auto-scrolling
- **Resizable columns** and responsive design
- **Status indicators** and packet counters
- **Intuitive controls** for capture management

## Installation

### Prerequisites
- Python 3.7 or higher
- Administrator/root privileges (for packet capture)

### Steps

1. **Clone or download** the project files to a directory
2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```
   Or manually install Scapy:
   ```bash
   pip install scapy
   ```

## Usage

### Running the Application

#### Quick Start
```bash
python main.py
```

#### Linux/macOS (with sudo for full privileges)
```bash
sudo python main.py
```

#### Windows (run as Administrator)
- Right-click Command Prompt → "Run as administrator"
- Navigate to the project directory
- Run: `python main.py`

### Application Workflow

1. **Select Network Interface**: Choose from detected network interfaces
2. **Choose Protocol Filter**: Filter by ALL, TCP, UDP, ICMP, HTTP, HTTPS, DNS, or ARP
3. **Start Capture**: Click "Start Capture" to begin monitoring
4. **Monitor Packets**: View real-time packet information in the table
5. **Save Results**: Export captured packets to PCAP files
6. **Stop/Clear**: Stop capture or clear current data as needed

### Interface Guide

#### Control Panel
- **Interface**: Select network interface for monitoring
- **Filter**: Choose protocol filter for focused analysis
- **Start Capture**: Begin packet capture
- **Stop Capture**: End current capture session
- **Clear**: Remove all displayed packets
- **Save PCAP**: Export packets for external analysis

#### Packet Display
- **TIME**: Timestamp of packet capture
- **SRC**: Source IP/MAC address
- **DST**: Destination IP/MAC address  
- **PROTO**: Identified protocol type
- **LEN**: Packet length in bytes
- **INFO**: Protocol-specific information

#### Status Bar
- **Status**: Current application state
- **Packet Count**: Total captured packets and queue status

## File Structure

```
packet-sniffer/
├── main.py              # Application entry point
├── gui.py               # Main GUI application
├── packet_sniffer.py    # Core sniffing functionality
├── packet_analyzer.py   # Packet analysis logic
├── config.py            # Configuration constants
├── requirements.txt     # Python dependencies
└── README.md           # This documentation
```

### Module Descriptions

#### `main.py`
- Application entry point with privilege and dependency checking
- Logging configuration and error handling
- Cross-platform compatibility checks

#### `gui.py`
- Complete GUI implementation using Tkinter
- User interface components and event handling
- Real-time packet display and controls

#### `packet_sniffer.py`
- Core packet capture using Scapy
- Thread management for non-blocking operation
- Packet storage and export functionality

#### `packet_analyzer.py`
- Protocol identification and analysis
- Packet information extraction
- Filtering logic implementation

#### `config.py`
- Application configuration constants
- Display settings and protocol definitions
- Customizable parameters

## Protocol Support

### Supported Protocols
- **TCP**: Transmission Control Protocol with flag analysis
- **UDP**: User Datagram Protocol
- **ICMP**: Internet Control Message Protocol
- **HTTP**: HyperText Transfer Protocol (basic detection)
- **HTTPS**: HTTP Secure (port 443 detection)
- **DNS**: Domain Name System queries/responses
- **ARP**: Address Resolution Protocol

### Protocol Information Displayed
- **TCP**: Flags (SYN, ACK, FIN, etc.) and sequence numbers
- **UDP**: Packet length information
- **ICMP**: Type and code values
- **DNS**: Query names and response data
- **HTTP/HTTPS**: Request methods and traffic identification
- **ARP**: Address resolution requests

## Troubleshooting

### Common Issues

#### "No interfaces found"
- **Linux**: Run with sudo privileges
- **Windows**: Run as Administrator
- **Check**: Network adapters are enabled

#### "Permission denied" errors
- Ensure running with administrator/root privileges
- Check firewall settings may be blocking access
- Verify Scapy installation is complete

#### "Scapy import error"
```bash
pip install scapy
# Or try:
pip install --upgrade scapy
```

#### Poor performance/freezing
- Reduce packet capture volume with BPF filters
- Clear packets periodically during long captures
- Close other network-intensive applications

### System Requirements
- **RAM**: Minimum 512MB available
- **CPU**: Any modern processor
- **Network**: Active network interface
- **OS**: Windows 7+, Linux 2.6+, macOS 10.9+

## Security Considerations

### Privileges
- Application requires elevated privileges for network access
- Only captures packets visible to the network interface
- Does not modify or inject network traffic

### Privacy
- All packet data remains local to your system
- No data is transmitted to external services
- Saved PCAP files contain captured network data

### Responsible Use
- Only monitor networks you own or have permission to analyze
- Respect privacy and legal requirements in your jurisdiction
- Use for educational, debugging, and authorized security analysis only

## Advanced Usage

### Custom Filtering
The application supports BPF (Berkeley Packet Filter) syntax for advanced filtering:
- `tcp port 80` - HTTP traffic only
- `host 192.168.1.1` - Specific host traffic
- `not broadcast` - Exclude broadcast packets

### Integration with Other Tools
Exported PCAP files can be analyzed with:
- **Wireshark**: Full-featured packet analyzer
- **tcpdump**: Command-line packet analyzer  
- **NetworkMiner**: Network forensics tool
- **Security Onion**: Network security monitoring

### Automation Potential
The modular design allows for:
- Custom protocol analyzers
- Automated threat detection
- Integration with SIEM systems
- Batch processing capabilities

## Contributing

This packet sniffer is designed with modularity and extensibility in mind. Areas for enhancement include:

- Additional protocol analyzers
- Packet detail view windows
- Statistical analysis features
- Alert/notification systems
- Database storage options
- REST API interface

## License

This project is provided for educational and authorized security analysis purposes. Users are responsible for compliance with local laws and regulations regarding network monitoring.

## Support

For issues, questions, or contributions:
1. Check the troubleshooting section
2. Review the configuration options
3. Examine log files for detailed error information
4. Ensure proper privileges and dependencies