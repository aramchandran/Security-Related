from scapy.all import *

addr=raw_input("Enter the IP address: ")

a = (IP(dst=str(addr),id=1111)/TCP(flags="S",sport=RandShort(),dport=139))
ans = srloop(a,timeout=4)

