# Network Packet Sniffer

A Python-based network packet sniffer that captures and analyzes live network traffic using the Scapy library.

## Features

- Real-time packet capture
- Source and destination IP extraction
- Protocol detection (TCP, UDP, ICMP, DNS)
- Port detection
- HTTP / HTTPS traffic identification
- Packet size monitoring
- Basic port scan detection
- Suspicious traffic alerts

## Technologies Used

- Python
- Scapy
- Networking
- Cybersecurity

## Installation

Clone the repository:

```bash
git clone https://github.com/YOUR_USERNAME/network-packet-sniffer.git
cd network-packet-sniffer
```

Install dependencies:

```bash
pip install -r requirements.txt
```

## Usage

Run with root privileges:

```bash
sudo python3 sniffer.py
```

Optional interface:

```bash
sudo python3 sniffer.py -i en0
```

## Example Output

```
[+] Packet Captured
Source IP: 192.168.1.10
Destination IP: 8.8.8.8
Protocol: TCP
Source Port: 49832
Destination Port: 443
```

## Educational Purpose

This project demonstrates how packet sniffing works and how network traffic can be analyzed for basic security monitoring.
