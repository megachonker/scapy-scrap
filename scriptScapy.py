#! /usr/bin/env python
from scapy.all import *

def pkt_callback(pkt):
	print("\n\nNew:\n")
	if int(pkt.getlayer(ARP).op) == 1:
		print("ARP request")
	else:
		print("ARP Reply")
	print("Source:")
	print(pkt.getlayer(ARP).psrc)
	print(pkt.getlayer(ARP).hwsrc)
	print("Destination:")
	print(pkt.getlayer(ARP).pdst)
	print(pkt.getlayer(ARP).hwdst)
sniff(prn=pkt_callback, filter="arp", store=0)