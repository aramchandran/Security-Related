from scapy.all import *

add= raw_input("Enter the IP address and subnet in the form: 0.0.0.0/30: ")
hst=IP(dst=str(add))/TCP(dport=[80,53])
add = [p for p in hst]
for b in add[2:len(add)-2]:
 b.show()	
