from scapy.all import IP, sniff, Ether
from collections import defaultdict
import os
import platform
import argparse
from colorama import Fore

# Colorama color definitions
green = Fore.GREEN
red = Fore.RED
blue = Fore.BLUE
yellow = Fore.YELLOW
cyan = Fore.CYAN

# Function to display the banner
def get_banner():
    banner = """
           _____  _       ___    ___   ___     ____  __ __   ____  ____   ___   
          |     || |     /   \  /   \ |   \   /    ||  |  | /    ||    \ |   \  
          |   __|| |    |     ||     ||    \ |   __||  |  ||  o  ||  D  )|    \ 
          |  |_  | |___ |  O  ||  O  ||  D  ||  |  ||  |  ||     ||    / |  D  |
          |   _] |     ||     ||     ||     ||  |_ ||  :  ||  _  ||    \ |     |
          |  |   |     ||     ||     ||     ||     ||     ||  |  ||  .  \|     |
          |__|   |_____| \___/  \___/ |_____||___,_| \__,_||__|__||__|\_||_____|
                                                                                
    """
    print(blue + banner)

# Function to parse command-line arguments
def get_arguments():
    parse = argparse.ArgumentParser()
    parse.add_argument('-i', '--interface', help="Specify your interface here, e.g., eth0, wlan0, Wi-Fi")
    return parse.parse_args()

# Global variables
ip_limit = 20
count_ip = defaultdict(int)

# Packet capture callback function
def captured_packets(packet):
    if packet.haslayer(Ether) and packet.haslayer(IP):
        ip = packet[IP].src
        mac = packet[Ether].src  # Correct method to retrieve MAC address
        count_ip[ip] += 1
        print(cyan + f"[*] Packet from {ip} \t {mac}, packet count: {count_ip[ip]}")

        if count_ip[ip] > ip_limit:
            print(red + f"[+] DDoS attack is coming from {ip} and their MAC {mac}")
            if platform.system() == "Linux":
                block_ip_linux(ip)
            elif platform.system() == "Windows":
                block_ip_in_win(ip)
        else:
            print(green + "[-] No DDoS attack detected.")

# Function to block IP in Linux using iptables
def block_ip_linux(ip):
    print(blue + f"[*] Blocking {ip} on Linux...")
    os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")

# Function to block IP on Windows
def block_ip_in_win(ip):
    print(blue + f"[*] Blocking {ip} in Windows...")
    os.system(f"netsh Advfirewall firewall add rule name=\"BLOCK {ip}\" dir=in action=block remoteip={ip}")

# Main script execution
if __name__ == "__main__":
    get_banner()
    args = get_arguments()

    try:
        if args.interface:
            if platform.system() == "Linux":
                print(green + "[+] Running on Linux")
                sniff(prn=captured_packets, store=0, iface=args.interface)
            elif platform.system() == "Windows":
                print(green + "[+] Running on Windows")
                sniff(prn=captured_packets, store=0, iface=args.interface)
            else:
                print(red + "[-] No Supported Platform Found!!")
        else:
            print(yellow + "[!] Please specify an argument or option")
            print(yellow + "[!] Usage: python ddosdefender.py -i eth0,Wlan0,wlan1,Wi-Fi")

    except KeyboardInterrupt:
        print(red + "\n[!] Exiting program...")

    except Exception as e:
        print(red + f"[!] Error: {e}") 
