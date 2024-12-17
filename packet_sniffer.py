# Simple Network Packet Sniffer

from scapy.all import sniff, IP, TCP, UDP, ICMP, wrpcap
from datetime import datetime

# Counters for packet summary
packet_count = {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0}

# Function to process captured packets
def process_packet(packet):
    print("====== New Packet ======")
    packet_size = len(packet)  # Calculate packet size

    # Check if the packet has an IP layer
    if IP in packet:
        print(f"Source IP: {packet[IP].src}")
        print(f"Destination IP: {packet[IP].dst}")
        print(f"Packet Size: {packet_size} bytes")  # Display packet size
        
        # Check for TCP protocol
        if TCP in packet:
            print("Protocol: TCP")
            print(f"Source Port: {packet[TCP].sport}")
            print(f"Destination Port: {packet[TCP].dport}")
            packet_count["TCP"] += 1  # Increment TCP count
        
        # Check for UDP protocol
        elif UDP in packet:
            print("Protocol: UDP")
            print(f"Source Port: {packet[UDP].sport}")
            print(f"Destination Port: {packet[UDP].dport}")
            packet_count["UDP"] += 1  # Increment UDP count
        
        # Check for ICMP protocol
        elif ICMP in packet:
            print("Protocol: ICMP")
            packet_count["ICMP"] += 1  # Increment ICMP count
        
        # Other protocols
        else:
            print("Protocol: Other")
            packet_count["Other"] += 1  # Increment Other count
    else:
        print("No IP Layer Found")
        packet_count["Other"] += 1

# Start packet sniffing
filter_type = input("Enter protocol to filter (tcp/udp/icmp/all): ").lower()
packet_filter = filter_type if filter_type in ["tcp", "udp", "icmp"] else ""
print("Starting Packet Sniffer... Press Ctrl+C to stop.")
packets = sniff(prn=process_packet, count=50)

# Save captured packets to a file for Wireshark analysis
wrpcap("captured_traffic.pcap", packets)
print("\nPackets saved to captured_traffic.pcap")

# Display Packet Summary
print("\n===== Packet Capture Summary =====")
print(f"TCP Packets: {packet_count['TCP']}")
print(f"UDP Packets: {packet_count['UDP']}")
print(f"ICMP Packets: {packet_count['ICMP']}")
print(f"Other Packets: {packet_count['Other']}")

# Timestamp
print()
print(f"Timestamp: {datetime.now()}")
