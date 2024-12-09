from scapy.all import sniff, IP, TCP, UDP

def process_packet(packet):
     if IP in packet:
         ip_layer = packet[IP]
         print(f"Source IP: {ip_layer.src}")
         print(f"Destination IP: {ip_layer.dst}")
         if TCP in packet:
             tcp_layer = packet[TCP]
             print(f"Protocol: TCP")
             print(f"Source Port: {tcp_layer.sport}")
             print(f"Destination Port: {tcp_layer.dport}")
             print(f"Payload: {tcp_layer.payload}")
         elif UDP in packet:
             udp_layer = packet[UDP]
             print(f"Protocol: UDP")
             print(f"Source Port: {udp_layer.sport}")
             print(f"Destination Port: {udp_layer.dport}")
             print(f"Payload: {udp_layer.payload}")
         print("\n")
 
         
def main():
     print("Starting packet sniffer...")
     sniff(prn=process_packet, store=False)
 
     
if __name__ == "__main__":
     main()