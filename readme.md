FloodGuard - DDoS Defender Tool

![FloodGuard](https://img.shields.io/badge/Version-1.0-green.svg) ![License](https://img.shields.io/badge/License-MIT-blue.svg)

FloodGuard is a Python-based DDoS defender tool designed to monitor incoming traffic in real-time, detect Distributed Denial of Service (DDoS) attacks, and block malicious IP addresses from flooding your network. This tool supports both Linux and Windows platforms and uses iptables (on Linux) or Windows Firewall (on Windows) to block attackers.

Features

DDoS Detection: Detects suspicious activity based on packet rate per IP.
Real-time Monitoring: Monitors incoming traffic in real-time using the `scapy` library.
IP Blocking: Automatically blocks the attacking IP when it exceeds a predefined packet limit using iptables (Linux) or Windows Firewall.
Custom Interface: Specify the network interface to monitor traffic.
Cross-platform: Works on both Linux and Windows systems.

Installation

1. Clone this repository:

bash
	   	git clone https://github.com/yourusername/FloodGuard.git

Install the required dependencies:

    bash

	    pip install -r requirements.txt

Dependencies include:
scapy
colorama
argparse

    (Optional) For Linux systems, ensure you have iptables installed and that you have sudo privileges to block traffic.

Usage

To run FloodGuard, specify the network interface to monitor:

bash

	sudo python3 floodguard.py -i <interface>

For example, to monitor eth0 on Linux:

bash

	sudo python3 floodguard.py -i eth0

Available Options

    -i, --interface: Specify the network interface (e.g., eth0, wlan0, Wi-Fi).

Example Output

less

[*] Packet from 192.168.0.101    aa:bb:cc:dd:ee:ff, packet count: 5
[-] No DDoS attack detected.
[*] Packet from 192.168.0.101    aa:bb:cc:dd:ee:ff, packet count: 21
[+] DDoS attack is coming from 192.168.0.101 and their MAC aa:bb:cc:dd:ee:ff
[*] Blocking 192.168.0.101 on Linux...

Testing

To test this tool, you can simulate a DDoS attack using tools like hping3, Scapy, or custom scripts to send a flood of packets from a machine within the network.
Example using hping3:

bash

	sudo hping3 -S --flood -V -p 80 <target_ip>

FloodGuard will detect and block the attack after the packet count exceeds the limit (default is 20 packets).
Future Improvements

    Add support for more sophisticated detection algorithms.
    Integrate support for additional firewall solutions.
    Add more flexible threshold and traffic analysis mechanisms.

Contributing

Contributions, issues, and feature requests are welcome! Feel free to check the issues page or submit a pull request.
License

FloodGuard is licensed under the MIT License. See the LICENSE file for more details.
