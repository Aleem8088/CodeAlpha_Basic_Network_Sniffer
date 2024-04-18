import scapy.all as scapy

def sniff_packets(interface):
    scapy.sniff(iface=interface, store=False, prn=process_packet)

def process_packet(packet):
    if packet.haslayer(scapy.IP):
        ip_src = packet[scapy.IP].src
        ip_dst = packet[scapy.IP].dst
        protocol = packet[scapy.IP].proto
        print(f"[*] {ip_src} -> {ip_dst} Protocol: {protocol}")

    if packet.haslayer(scapy.TCP):
        src_port = packet[scapy.TCP].sport
        dst_port = packet[scapy.TCP].dport
        print(f"    [+] TCP Source Port: {src_port} Destination Port: {dst_port}")

    elif packet.haslayer(scapy.UDP):
        src_port = packet[scapy.UDP].sport
        dst_port = packet[scapy.UDP].dport
        print(f"    [+] UDP Source Port: {src_port} Destination Port: {dst_port}")

    elif packet.haslayer(scapy.ICMP):
        icmp_type = packet[scapy.ICMP].type
        icmp_code = packet[scapy.ICMP].code
        print(f"    [+] ICMP Type: {icmp_type} Code: {icmp_code}")

    elif packet.haslayer(scapy.IPv6):
        print("    [+] IPv6 packet")

    elif packet.haslayer(scapy.ARP):
        src_mac = packet[scapy.ARP].hwsrc
        dst_mac = packet[scapy.ARP].hwdst
        print(f"    [+] ARP Source MAC: {src_mac} Destination MAC: {dst_mac}")

    elif packet.haslayer(scapy.Ether):
        print("    [+] Ethernet frame")

    elif packet.haslayer(scapy.DNS):
        dns_query = packet[scapy.DNS].qd.qname
        print(f"    [+] DNS Query: {dns_query}")

    else:
        print(f"    [+] Unknown protocol")




# Start sniffing on a specific interface (in this case WI-Fi 2)
sniff_packets("Wi-Fi 2")

