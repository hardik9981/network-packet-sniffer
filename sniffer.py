import argparse
from scapy.all import sniff
from analyzer import analyze_packet
from utils import show_stats


def start_sniffer(interface=None):

    print("\n==============================")
    print(" Network Packet Sniffer Started ")
    print("==============================")
    print("Press CTRL+C to stop\n")

    try:
        sniff(prn=analyze_packet, iface=interface, store=False)

    except KeyboardInterrupt:
        print("\nStopping sniffer...\n")
        show_stats()


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Python Network Packet Sniffer")

    parser.add_argument(
        "-i",
        "--interface",
        help="Network interface (example: en0)",
        required=False
    )

    args = parser.parse_args()

    start_sniffer(args.interface)