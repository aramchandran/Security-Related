import sys
import os
from scapy.all import *

s = raw_input("Enter the IP address: ")
ans, unans = sr(IP(dst=str(s),ttl=(2,5),id=RandShort())/TCP(flags=0x2))
for snd,rcv in ans:
 print snd.ttl, rcv.src, isinstance(rcv.payload, TCP)
