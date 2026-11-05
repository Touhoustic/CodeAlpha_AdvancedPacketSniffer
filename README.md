# Advanced Packet Sniffer

![Python](https://img.shields.io/badge/Python-3.7+-blue?style=flat-square)
![Scapy](https://img.shields.io/badge/Scapy-2.5+-green?style=flat-square)
![GUI](https://img.shields.io/badge/GUI-Tkinter-lightgrey?style=flat-square)

A Python GUI application that captures and analyzes network traffic in real time. It shows packet details (source and destination IPs, protocols, ports, payloads) to help understand how data flows through a network.

> **Authorized use only.** Capture traffic only on networks you own or have explicit permission to monitor.

## Features

- Real-time packet capture on any network interface
- Live statistics dashboard with a protocol breakdown
- Color-coded protocol display
- Filtering by protocol, IP address or port, applied live without stopping the capture
- Packet inspection with three views: protocol layers, hex dump and ASCII payload
- Multi-protocol support: TCP, UDP, ICMP, ARP, DNS and HTTP
- PCAP export for analysis in Wireshark or other tools

## Requirements

- Python 3.7 or higher
- [Scapy](https://scapy.net/)
- Tkinter (ships with Python; on Debian/Ubuntu install `python3-tk`)
- Administrator/root privileges for packet capture (plus [Npcap](https://npcap.com/) on Windows)

## Installation

```bash
git clone https://github.com/Touhoustic/CodeAlpha_AdvancedPacketSniffer.git
cd CodeAlpha_AdvancedPacketSniffer
pip install -r requirements.txt

# Linux only, if Tkinter is missing:
sudo apt-get install python3-tk
```

## Usage

Run with elevated privileges.

Linux/macOS:
```bash
sudo python3 packet_sniffer_aug.py
```

Windows (terminal opened as Administrator):
```bash
python packet_sniffer_aug.py
```

### Workflow

1. Select the network interface from the dropdown
2. Click **Start Capture**
3. Optionally narrow the view with filters
4. Click any packet to inspect its layers, hex dump and ASCII payload
5. Save the capture as a `.pcap` file for later analysis
6. Click **Stop Capture** when finished

## Supported protocols

| Protocol | Analysis |
|---|---|
| TCP | Header analysis with flag breakdown |
| UDP | Ports and length |
| ICMP | Type and code identification |
| ARP | Requests and replies |
| DNS | Query and response detection |
| HTTP | Basic request/response parsing |

## How it works

Scapy handles capture and dissection, and a Tkinter GUI displays the results. Capture runs in a separate thread so the interface stays responsive. Each packet is analyzed layer by layer (Ethernet, network, transport, application) and kept in memory until exported to PCAP.

## Limitations

- Encrypted payloads (HTTPS, SSH) appear as opaque binary data
- Captured packets are stored in memory, so very long captures on busy networks use a lot of RAM
- HTTP parsing is basic and does not reassemble TCP streams

## Disclaimer

This tool is for learning and for troubleshooting networks you own or are authorized to monitor. Capturing traffic without permission may be illegal.
