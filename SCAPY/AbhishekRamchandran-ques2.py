from scapy.all import *

addr=raw_input("Enter the IP address: ")
srloop(IP(dst=addr)/ICMP(), count= 4)

