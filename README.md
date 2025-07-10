# Network Sniffer Project

## Author

Syed Muhammad Qammar Abbas Zaidi

## Overview

This project implements a Python-based network sniffer using Scapy to capture and analyze HTTP (port 80) and HTTPS (port 443) packets. It logs packet details, saves captured packets to a PCAP file for Wireshark analysis, and flags external IP addresses for potential suspicious activity.

## Environment Setup

### System Update and Package Installation

Update the system and install required packages:

```bash
sudo apt-get update
sudo apt-get install python3 python3-pip
sudo pip3 install scapy
sudo pip3 install virtualenv
```

### Virtual Environment Creation and Activation

Create and activate a virtual environment to manage dependencies:

```bash
# First go to the Desktop
cd Desktop

# Create virtual environment
virtualenv scapy_env

# Activate virtual environment
source scapy_env/bin/activate
```

## Running the Sniffer

### Generating Traffic

In one terminal, generate HTTP and HTTPS traffic:

```bash
curl http://example.com 
curl https://google.com
```

### Running the Sniffer Script

In another terminal, activate the virtual environment and run the sniffer:

```bash
source scapy_env/bin/activate
sudo python sniffer.py
```

- When prompted, enter the network interface (e.g., `eth0`).

## Features

- Captures 20 HTTP/HTTPS packets with a 60-second timeout.
- Displays and logs source/destination IPs, protocol, and payload (first 100 characters).
- Saves packets to `captured_packets.pcap` for Wireshark analysis.
- Logs details to `sniffer_errors.log`.
- Warns about external IPs (non-192.168.x.x).
- Tracks and summarizes packet counts (HTTP, HTTPS, Other).

## Risks and Mitigations

- **Risk**: Potential capture of sensitive unencrypted data.
- **Mitigation**: Use HTTPS, VPNs, or other encrypted protocols.

## Testing Environment

- OS: Kali Linux
- Python: 3.x
- Scapy: 2.6.1

## Files Included

- `sniffer.py`: Main sniffer script.
- `captured_packets.pcap`: Captured packets.
- `sniffer_errors.log`: Log file.

## Editing Files with Nano

To edit files using nano:

```bash
nano sniffer.py
```

- Use arrow keys to navigate.
- Make changes.
- Save: `Ctrl+O`, then `Enter`.
- Exit: `Ctrl+X`.

## Analyzing Packets with Wireshark

To analyze captured packets:

```bash
wireshark captured_packets.pcap
```

- Filter for HTTP: `tcp.port == 80`
- Filter for HTTPS: `tcp.port == 443`
