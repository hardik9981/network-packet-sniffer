from collections import defaultdict

stats = defaultdict(int)

COMMON_PORTS = {
    80: "HTTP",
    443: "HTTPS",
    53: "DNS",
    22: "SSH",
    21: "FTP",
    25: "SMTP",
    110: "POP3"
}

def update_stats(protocol):
    stats["total"] += 1
    stats[protocol] += 1

def show_stats():

    print("\n========= Traffic Statistics =========")
    print(f"Total Packets: {stats['total']}")
    print(f"TCP: {stats['TCP']}")
    print(f"UDP: {stats['UDP']}")
    print(f"ICMP: {stats['ICMP']}")
    print(f"DNS: {stats['DNS']}")
    print("=====================================\n")

def port_name(port):
    return COMMON_PORTS.get(port, "Unknown")