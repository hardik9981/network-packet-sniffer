from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.http import HTTPRequest
from utils import update_stats, port_name
from collections import defaultdict
import time

scan_tracker = defaultdict(list)
SCAN_THRESHOLD = 10
SCAN_TIME_WINDOW = 5


def detect_port_scan(src_ip, dst_port):
    current_time = time.time()

    scan_tracker[src_ip].append((dst_port, current_time))

    scan_tracker[src_ip] = [
        (port, t) for port, t in scan_tracker[src_ip]
        if current_time - t < SCAN_TIME_WINDOW
    ]

    unique_ports = {port for port, t in scan_tracker[src_ip]}

    if len(unique_ports) >= SCAN_THRESHOLD:
        print("\n⚠️ ALERT: Possible Port Scan Detected!")
        print(f"Source IP: {src_ip}")
        print(f"Ports scanned: {len(unique_ports)}\n")

        scan_tracker[src_ip].clear()


def analyze_packet(packet):

    if IP not in packet:
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    packet_len = len(packet)

    protocol = "OTHER"
    src_port = None
    dst_port = None

    # TCP
    if packet.haslayer(TCP):
        protocol = "TCP"
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        detect_port_scan(src_ip, dst_port)

    # UDP
    elif packet.haslayer(UDP):
        protocol = "UDP"
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    # ICMP
    elif packet.haslayer(ICMP):
        protocol = "ICMP"

    # DNS detection
    if packet.haslayer(DNS) and packet.haslayer(DNSQR):
        protocol = "DNS"
        domain = packet[DNSQR].qname.decode(errors="ignore")
        print("\n🌐 DNS Query Detected")
        print(f"Domain Requested: {domain}")

    # HTTP detection
    if packet.haslayer(HTTPRequest):
        host = packet[HTTPRequest].Host.decode(errors="ignore")
        path = packet[HTTPRequest].Path.decode(errors="ignore")

        print("\n🌐 HTTP Request Detected")
        print(f"Host: {host}")
        print(f"Path: {path}")

    update_stats(protocol)

    print("\n==============================")
    print("[+] Packet Captured")
    print("==============================")
    print(f"Source IP: {src_ip}")
    print(f"Destination IP: {dst_ip}")
    print(f"Packet Length: {packet_len}")
    print(f"Protocol: {protocol}")

    if src_port:
        print(f"Source Port: {src_port} ({port_name(src_port)})")

    if dst_port:
        print(f"Destination Port: {dst_port} ({port_name(dst_port)})")