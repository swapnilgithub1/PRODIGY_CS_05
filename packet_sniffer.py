#pip install scapy
from scapy.all import sniff, IP, TCP, UDP

# Function to process each captured packet
def process_packet(packet):
    # Check if the packet has an IP layer
    if IP in packet:
        # Extract the IP layer from the packet
        ip_layer = packet[IP]
        # Print the source IP address
        print(f"Source IP: {ip_layer.src}")
        # Print the destination IP address
        print(f"Destination IP: {ip_layer.dst}")
        # Check if the packet has a TCP layer
        if TCP in packet:
            # Extract the TCP layer from the packet
            tcp_layer = packet[TCP]
            # Print protocol type
            print(f"Protocol: TCP")
            # Print the source port
            print(f"Source Port: {tcp_layer.sport}")
            # Print the destination port
            print(f"Destination Port: {tcp_layer.dport}")
            # Print the payload of the packet
            print(f"Payload: {tcp_layer.payload}")
        # Check if the packet has a UDP layer
        elif UDP in packet:
            # Extract the UDP layer from the packet
            udp_layer = packet[UDP]
            # Print protocol type
            print(f"Protocol: UDP")
            # Print the source port
            print(f"Source Port: {udp_layer.sport}")
            # Print the destination port
            print(f"Destination Port: {udp_layer.dport}")
            # Print the payload of the packet
            print(f"Payload: {udp_layer.payload}")
        # Print a new line for readability
        print("\n")

# Main function to start the packet sniffer
def main():
    # Print a starting message
    print("Starting packet sniffer...")
    # Start sniffing packets and call process_packet for each packet
    sniff(prn=process_packet, store=False)

# If the script is run directly, call the main function
if __name__ == "__main__":
    main()
