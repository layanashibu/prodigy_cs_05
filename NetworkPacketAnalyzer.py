from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto

        # Determine the protocol
        if protocol == 6:
            protocol_name = "TCP"
        elif protocol == 17:
            protocol_name = "UDP"
        elif protocol == 1:
            protocol_name = "ICMP"
        else:
            protocol_name = "Other"

        print(f"Source IP: {ip_src} -> Destination IP: {ip_dst} | Protocol: {protocol_name}")

        # Print payload if it exists
        if TCP in packet or UDP in packet:
            payload = packet[TCP].payload if TCP in packet else packet[UDP].payload
            if payload:
                print(f"Payload: {bytes(payload)}\n")

# Sniff the network interface (e.g., "eth0" or "wlan0")
sniff(filter="ip", prn=packet_callback, store=0)
