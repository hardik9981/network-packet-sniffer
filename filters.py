def apply_filter(packet, protocol_filter):

    if protocol_filter is None:
        return True

    if protocol_filter == "tcp" and packet.haslayer("TCP"):
        return True

    if protocol_filter == "udp" and packet.haslayer("UDP"):
        return True

    if protocol_filter == "icmp" and packet.haslayer("ICMP"):
        return True

    return False