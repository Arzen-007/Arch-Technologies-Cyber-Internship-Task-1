from scapy.all import *
import sys
import logging
import time

# Configure logging to save packet details and errors to a file
logging.basicConfig(filename='sniffer_errors.log', level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Dictionary to track the count of HTTP, HTTPS, and other packets
packet_count = {'HTTP': 0, 'HTTPS': 0, 'Other': 0}

def get_network_interfaces():
    """Fetches a list of available network interfaces using Scapy."""
    try:
        interfaces = get_if_list()  # Get list of network interfaces
        if not interfaces:
            raise Exception("No network interfaces found.")
        return interfaces
    except Exception as e:
        logging.error(f"Error fetching interfaces: {e}")
        print(f"Error: Could not fetch interfaces - {e}")
        return []

def packet_callback(packet):
    """Processes each captured packet, displays details, and logs them."""
    try:
        # Get current timestamp for packet logging
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
        
        # Check if packet has IP layer
        if packet.haslayer(IP):
            src_ip = packet[IP].src  # Source IP address
            dst_ip = packet[IP].dst  # Destination IP address
            proto = packet[IP].proto  # Protocol number (6 for TCP)
            print(f"[{timestamp}] Source IP: {src_ip} -> Destination IP: {dst_ip} | Protocol: {proto}")
            logging.info(f"[{timestamp}] Captured: Source IP: {src_ip} -> Destination IP: {dst_ip} | Protocol: {proto}")
            
            # Check for external IPs (warn if either IP is not in 192.168.x.x range)
            if not (src_ip.startswith("192.168.") and dst_ip.startswith("192.168.")):
                print(f"[{timestamp}] Warning: External IP detected, possible suspicious activity.")
                logging.warning(f"[{timestamp}] External IP detected: {src_ip} -> {dst_ip}")
            
            # Check if packet has TCP layer
            if packet.haslayer(TCP):
                # Identify packet type based on port (80 for HTTP, 443 for HTTPS)
                if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                    packet_count['HTTP'] += 1
                    print(f"[{timestamp}] Packet Type: HTTP")
                elif packet[TCP].dport == 443 or packet[TCP].sport == 443:
                    packet_count['HTTPS'] += 1
                    print(f"[{timestamp}] Packet Type: HTTPS")
                else:
                    packet_count['Other'] += 1
                    print(f"[{timestamp}] Packet Type: Other TCP")
                
                # Get TCP payload (data carried in the packet)
                payload = packet[TCP].payload
                if payload:
                    print(f"[{timestamp}] TCP Payload (first 100 chars): {str(payload)[:100]}")
                    logging.info(f"[{timestamp}] TCP Payload: {str(payload)[:100]}")
                else:
                    print(f"[{timestamp}] TCP Payload: Empty")
                    logging.info(f"[{timestamp}] TCP Payload: Empty")
                
                # Check for Raw layer (contains application data)
                if packet.haslayer(Raw):
                    raw_data = str(packet[Raw].load)[:100]  # Limit to 100 chars
                    if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                        print(f"[{timestamp}] Raw HTTP Data: {raw_data}")
                        logging.info(f"[{timestamp}] Raw HTTP Data: {raw_data}")
                    elif packet[TCP].dport == 443 or packet[TCP].sport == 443:
                        print(f"[{timestamp}] Raw TLS Data: {raw_data}")
                        logging.info(f"[{timestamp}] Raw TLS Data: {raw_data}")
            
            else:
                # Non-TCP IP packets (e.g., UDP, ICMP)
                packet_count['Other'] += 1
                print(f"[{timestamp}] Packet Type: Non-TCP")
        
        else:
            # Non-IP packets (e.g., ARP)
            print(f"[{timestamp}] Non-IP packet captured.")
            packet_count['Other'] += 1
    except Exception as e:
        logging.error(f"[{timestamp}] Error processing packet: {e}")
        print(f"[{timestamp}] Error processing packet: {e}")

def main():
    """Main function to run the network sniffer."""
    try:
        # Display welcome message with start time
        print("Network Sniffing by Zaidi")
        print(f"Started at: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Fetch available network interfaces
        interfaces = get_network_interfaces()
        if not interfaces:
            print("No interfaces available. Exiting...")
            sys.exit(1)
        
        # Display available interfaces to user
        print("Available network interfaces:", interfaces)
        interface = input("Enter the network interface to sniff (e.g., eth0): ")

        # Validate the selected interface
        if interface not in interfaces:
            raise ValueError(f"Invalid interface: {interface}. Available: {interfaces}")

        print(f"Starting network sniffer on {interface}...")
        print("Capturing 20 HTTP/HTTPS packets (ports 80/443)... Press Ctrl+C to stop early.")

        # Sniff HTTP and HTTPS packets (ports 80 and 443)
        packets = sniff(iface=interface, filter="tcp port 80 or tcp port 443", prn=packet_callback, count=20, timeout=60)
        
        # Save captured packets to a PCAP file for Wireshark analysis
        wrpcap("captured_packets.pcap", packets)
        print("Packets saved to captured_packets.pcap")

        # Print summary of captured packets
        print(f"\nSummary: {packet_count['HTTP']} HTTP packets, {packet_count['HTTPS']} HTTPS packets, {packet_count['Other']} other packets")
        print("Sniffing complete.",
              "Check 'sniffer_errors.log' for details.")

    except KeyboardInterrupt:
        # Handle user stopping the sniffer with Ctrl+C
        print("\nSniffing stopped by user.")
        logging.info("Sniffing stopped by user.")
        print(f"Summary: {packet_count['HTTP']} HTTP packets, {packet_count['HTTPS']} HTTPS packets, {packet_count['Other']} other packets")
    except PermissionError:
        # Handle missing root permissions
        print("Error: Run this script with sudo (root permissions required).")
        logging.error("PermissionError: Root permissions required.")
        sys.exit(1)
    except ValueError as ve:
        # Handle invalid interface selection
        print(f"Error: {ve}")
        logging.error(f"ValueError: {ve}")
        sys.exit(1)
    except Exception as e:
        # Handle any unexpected errors
        print(f"Error: {e}")
        logging.error(f"Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
