#! /usr/bin/env python
import random
from scapy.all import *
for x in range(1,65536):
	packet = IP(src="192.168.0.26", dst="192.168.0.25")/UDP(sport=random.randrange(1,65536)	, dport=x)
	rep = sr1(packet,verbose=False,inter=0.3,retry=3,timeout=0.1)
	if(rep is None):
		print("port:"+str(x)+" touver !")#+str(rep.show()))
input("espace  pour quiter")
