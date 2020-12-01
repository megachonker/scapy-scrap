#! /usr/bin/env python
from scapy.all import *
tableaux=["NULL"]
for x in range(1,65536):
	packet = IP(src="192.168.0.26", dst="192.168.0.25")/TCP(dport=x)
	rep = sr1(packet,verbose=False)
	flag=rep.getlayer(TCP).flags
	tableaux.append(flag)
	#print("test du  port "+str(x))
	#print("port:"+str(x)+"\n flags:"+str(flag))
	if(flag!="RA"):
		print("port:"+str(x)+"ouver !")
print("list des port ouver:")
print(tableaux)
input("espace  pour quiter")
