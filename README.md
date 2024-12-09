# PRODIGY_CS_05
# NETWORK PACKET ANALYZER

## Description
This Python script is a basic packet sniffer tool that captures and analyzes network packets. It displays relevant information such as source and destination IP addresses, protocols, and payload data. This tool is designed for educational purposes and should be used responsibly and ethically.

## Features
- Captures network packets in real-time
- Analyzes packets to display:
  - Source IP address
  - Destination IP address
  - Protocol (TCP/UDP)
  - Source port
  - Destination port
  - Payload data

## Requirements
- Python 3.6 or higher
- `scapy` library

## Installation
1. **Install Python**: Make sure Python is installed. You can download it from [python.org](https://www.python.org/).
2. **Install Scapy**:
   - Open Command Prompt (Windows) or Terminal (macOS/Linux).
   - Run the following command:
     ```sh
     pip install scapy
     ```


## Example Output
```plaintext
Starting packet sniffer...
Source IP: 192.168.1.100
Destination IP: 192.168.1.1
Protocol: TCP
Source Port: 12345
Destination Port: 80
Payload: <Payload data>

Source IP: 10.0.0.2
Destination IP: 10.0.0.1
Protocol: UDP
Source Port: 1234
Destination Port: 53
Payload: <Payload data>
