#!/usr/bin/env python3

from scapy.all import *
import sys
import time
from datetime import datetime

# Ethical use disclaimer
print("""
=== Network Packet Sniffer ===
This tool is intended for EDUCATIONAL PURPOSES ONLY.
Use only on networks where you have explicit permission.
Unauthorized network monitoring may be illegal in your jurisdiction.
""")

# Configuration
interface = None  # Will be set by user input
packet_count = 100  # Default number of packets to capture
filter_protocol = None  # Optional protocol filter

def setup_sniffer():
    """Configure the sniffer settings"""
    global interface, packet_count, filter_protocol
    
    # Get network interface
    print("Available interfaces:", get_if_list())
    interface = input("Enter network interface to sniff (e.g., eth0, wlan0): ")
    
    # Get number of packets to capture
    try:
        packet_count_input = input("Enter number of packets to capture (default 100): ")
        packet_count = int(packet_count_input) if packet_count_input else 100
    except ValueError:
        print("Invalid input, using default of 100 packets")
        packet_count = 100
    
    # Get optional protocol filter
    filter_protocol = input("Enter protocol to filter (e.g., tcp, udp, icmp) or press Enter for all: ").lower()
    if not filter_protocol:
        filter_protocol = None

def analyze_packet(packet):
    """Analyze and display packet information"""
    try:
        # Get current timestamp
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Basic packet information
        print(f"\n[{timestamp}] New Packet Captured")
        print("-" * 50)
        
        # Check if packet has IP layer
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet[IP].proto
            
            print(f"Source IP: {src_ip}")
            print(f"Destination IP: {dst_ip}")
            
            # Identify protocol
            proto_name = {
                1: "ICMP",
                6: "TCP",
                17: "UDP"
            }.get(protocol, f"Unknown ({protocol})")
            print(f"Protocol: {proto_name}")
            
            # Port information if TCP or UDP
            if TCP in packet:
                print(f"Source Port: {packet[TCP].sport}")
                print(f"Destination Port: {packet[TCP].dport}")
            elif UDP in packet:
                print(f"Source Port: {packet[UDP].sport}")
                print(f"Destination Port: {packet[UDP].dport}")
            
            # Display payload if available
            if Raw in packet:
                payload = packet[Raw].load
                print(f"Payload (first 50 bytes): {payload[:50]}")
                try:
                    # Attempt to decode as ASCII
                    payload_text = payload.decode('ascii', errors='ignore')
                    print(f"Payload Text: {payload_text[:50]}")
                except:
                    print("Payload not ASCII-decodable")
        
        else:
            print("Non-IP packet captured")
            print(f"Summary: {packet.summary()}")
            
    except Exception as e:
        print(f"Error analyzing packet: {e}")

def main():
    """Main function to run the packet sniffer"""
    try:
        # Setup sniffer configuration
        setup_sniffer()
        
        # Verify interface
        if interface not in get_if_list():
            print(f"Error: Interface {interface} not found")
            sys.exit(1)
            
        print(f"\nStarting packet capture on {interface}")
        print(f"Capturing {packet_count} packets...")
        if filter_protocol:
            print(f"Filtering for {filter_protocol} protocol")
        
        # Start sniffing
        sniff(
            iface=interface,
            count=packet_count,
            filter=filter_protocol,
            prn=analyze_packet
        )
        
        print("\nCapture complete!")
        
    except PermissionError:
        print("Error: This script requires root/admin privileges")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    # Check for root privileges (Unix-like systems)
    if os.name != 'nt' and os.geteuid() != 0:
        print("This script requires root privileges. Please run with sudo.")
        sys.exit(1)
        
    main()
