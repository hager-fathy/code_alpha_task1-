# Simple Network Sniffer

A lightweight, command-line network packet sniffer built with Python and Scapy. This tool captures and analyzes live network packets, displaying detailed information about Ethernet, IP, TCP, UDP, ICMP, and ARP layers, including MAC addresses, IP addresses, ports, protocols, and payloads. It also identifies common application-layer protocols (e.g., HTTP, HTTPS, DNS) and provides real-time packet rate statistics.

## Features

- **Live Packet Capture**: Captures packets from the default network interface using Scapy.
- **Detailed Packet Analysis**:
  - **Ethernet**: Source and destination MAC addresses, EtherType.
  - **IP**: Source and destination IP addresses, protocol number.
  - **TCP**: Source and destination ports, sequence number, flags, and payload data (with hex preview).
  - **UDP**: Source and destination ports, payload data.
  - **ICMP**: Type and code (e.g., Ping Request/Reply).
  - **ARP**: Operation (who-has/is-at), sender and target IP/MAC addresses.
- **Application Detection**: Identifies protocols like HTTP, HTTPS, DNS, FTP, Telnet, and SMTP based on port numbers.
- **Real-Time Stats**: Displays packet count, capture duration, and packet rate (packets per second).
- **Console Output**: Prints packet details in a clear, organized format with separators.
- **Interrupt Handling**: Stops gracefully with Ctrl+C, showing a summary of captured packets and average rate.

## Prerequisites

### Software
- **Python 3.6+**: Ensure Python is installed.
- **Operating System**: Compatible with Windows, Linux, and macOS.
- **Root/Administrator Privileges**: Required for live packet capture due to raw socket access.

### Python Dependencies
Install the required Python package:
```bash
pip install scapy

System Dependencies

Windows:
Install Npcap for packet capture.


Linux/macOS:
Install libpcap:sudo apt-get install libpcap-dev  # Debian/Ubuntu
sudo yum install libpcap-devel   # CentOS/RHEL
brew install libpcap             # macOS with Homebrew





Installation

Download the Script:

Save the sniffer.py file to your desired directory.
Alternatively, clone the repository (if hosted):git clone <repository-url>
cd <repository-directory>




Install Dependencies:

Install Scapy:pip install scapy


Install Npcap (Windows) or libpcap (Linux/macOS) as described above.


Verify Setup:

Ensure Scapy imports correctly:python3 -c "from scapy.all import *"


If errors occur, verify Npcap/libpcap installation.



Usage

Run the Script:

Open a terminal and navigate to the directory containing sniffer.py.
Run with root/admin privileges:
Linux/macOS:sudo python3 sniffer.py


Windows: Run as Administrator (open Command Prompt or PowerShell as Administrator, then run):python sniffer.py






Capture Packets:

The script starts capturing packets immediately and displays details for each packet, including:
Packet number and timestamp.
Packet rate (packets per second).
Ethernet, IP, TCP, UDP, ICMP, or ARP layer information.
Application protocol (e.g., HTTP, DNS) if applicable.
Payload size and a hex preview (for TCP/UDP with data).


Example output:[Packet #1] - 2025-05-19 20:32:45
Packet rate: 1.00 packets/sec
Ethernet: 00:1a:2b:3c:4d:5e -> ff:ff:ff:ff:ff:ff, type: 0x806
ARP: who-has
192.168.1.100 (00:1a:2b:3c:4d:5e) -> 192.168.1.1 (00:00:00:00:00:00)
____________________________________________________________




Stop Capture:

Press Ctrl+C to stop capturing.
The script will display a summary:Capture stopped by user
Captured 10 packets in 5.23 seconds
Average rate: 1.91 packets/sec





Troubleshooting
No Packets Captured

Check Privileges:
Ensure you’re running with sudo (Linux/macOS) or as Administrator (Windows).
Error message: Error: [Errno 13] Permission denied indicates missing privileges.


Verify Network Interface:
The script uses the default interface. To list available interfaces:python3 -c "from scapy.all import get_if_list; print(get_if_list())"


If no packets appear, specify an interface by modifying the sniff call in main():sniff(iface="eth0", prn=pack_callback, store=0)  # Replace "eth0" with your interface


Check interface status with ifconfig (Linux/macOS) or ipconfig (Windows).


Generate Traffic:
Ensure the network is active. Run:ping 8.8.8.8

or open a browser to generate traffic.


Firewall:
Temporarily disable your firewall (e.g., Windows Defender, ufw on Linux) to rule out blocking.



Dependency Issues

Scapy Import Error:
Verify Scapy installation: pip show scapy.
Reinstall if needed: pip install scapy.


Npcap/libpcap Missing:
Windows: Install Npcap from https://nmap.org/npcap/.
Linux/macOS: Install libpcap (see System Dependencies).
Error message: No module named 'scapy' or libpcap not found.



Other Errors

Error Messages:
Check console output for errors like Error:Duke: ....
Share the full error message for assistance.


Slow Performance:
High-traffic networks may flood the console. Add a filter to sniff:sniff(filter="tcp port 80", prn=pack_callback, store=0)





Notes

Security: Packet sniffing may capture sensitive data (e.g., unencrypted passwords). Use only on networks you’re authorized to monitor.
Limitations: The script captures all packets by default, which may overwhelm the console on busy networks. Use BPF filters (e.g., tcp, icmp) to focus on specific traffic.
Customization:
Add filters in the sniff call to capture specific traffic:sniff(filter="tcp port 80", prn=pack_callback, store=0)


Modify pack_callback to log packets to a file instead of printing.



Example Output
Simple Network Sniffer
Press Ctrl+C to stop capturing packets
____________________________________________________________

[Packet #1] - 2025-05-19 20:32:45
Packet rate: 1.00 packets/sec
Ethernet: 00:1a:2b:3c:4d:5e -> ff:ff:ff:ff:ff:ff, type: 0x806
ARP: who-has
192.168.1.100 (00:1a:2b:3c:4d:5e) -> 192.168.1.1 (00:00:00:00:00:00)
____________________________________________________________

[Packet #2] - 2025-05-19 20:32:46
Packet rate: 1.50 packets/sec
IP: 192.168.1.100 -> 8.8.8.8, proto: 1
ICMP: Type 8, Code 0
Echo Request (Ping)
____________________________________________________________




