# Advanced Packet Sniffer

A Python GUI application that captures and analyzes network traffic in real-time, displaying packet details including source/destination IPs, protocols, ports, and payloads to help understand how data flows through networks.

## Features

- Real-time packet capture on any network interface
- Live statistics dashboard showing protocol breakdown
- Color-coded protocol display for easy identification
- Advanced filtering by protocol, IP address, or port number
- Detailed packet inspection with three views: protocol layers, hex dump, and ASCII payload
- Multi-protocol support: TCP, UDP, ICMP, ARP, DNS, and HTTP
- PCAP export for analysis in other tools like Wireshark

## Requirements

- Python 3.7 or higher
- Administrator/Root privileges for packet capture

### Dependencies

```bash
scapy
tkinter
```

## Installation

Clone the repository:
```bash
git clone https://github.com/Touhoustic/CodeAlpha-AdvancedPacketSniffer
```

Install dependencies:
```bash
pip install scapy
```

For Linux users:
```bash
sudo apt-get install python3-tk
```

## Usage

Run with elevated privileges:

Linux/Mac:
```bash
sudo python3 packet_sniffer_aug.py
```

Windows (as Administrator):
```bash
python packet_sniffer_aug.py
```

### Basic Workflow

1. Select the network interface from the dropdown menu
2. Click "Start Capture" to begin monitoring
3. Use filters to narrow down specific traffic (optional)
4. Click on any packet to view detailed information
5. Save the capture as a .pcap file for later analysis
6. Click "Stop Capture" when finished

## Supported Protocols

- **TCP** - Full header analysis with flag breakdown
- **UDP** - Port and length information
- **ICMP** - Type and code identification
- **ARP** - Address resolution requests and replies
- **DNS** - Query and response detection
- **HTTP** - Basic request/response parsing

## Technical Details

The application uses Scapy for packet capture and manipulation, with a Tkinter-based GUI for display. Packet capture runs in a separate thread to prevent UI blocking. All captured packets are stored in memory and can be exported to standard PCAP format.

### Filtering

Filters can be applied dynamically without stopping the capture. The application supports:
- Protocol filtering (TCP, UDP, ICMP, ARP, DNS, HTTP)
- IP address filtering (matches source or destination)
- Port number filtering (searches in packet info)

### Packet Analysis

Each packet is analyzed layer by layer:
- Ethernet layer (MAC addresses)
- Network layer (IP addresses, TTL, protocol)
- Transport layer (ports, flags, sequence numbers)
- Application layer (HTTP, DNS detection)
- Raw payload extraction

## Important Notes

- Requires administrator or root privileges to capture packets
- Only use on networks you own or have explicit permission to monitor
- High traffic volumes may impact performance
- Encrypted payloads will show as binary data


## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.
