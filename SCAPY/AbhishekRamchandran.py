from scapy.all import *
import sys
import os
add= raw_input("Enter the IP address and subnet in the form: 0.0.0.0/30: ")
tcp_open = []
tcp_closed = []
tcp_filtered = []

udp_open = []
udp_closed = []
udp_open_filtered = []

def TCP_PACKET_ANALYSIS(add):
	for dst_port in xrange(1,101):
		src_port = RandShort()
		if(dst_port == 25 or dst_port == 50 or dst_port == 75):
			print dst_port,"%","Done."		
		hst=sr1(IP(dst=str(add))/TCP(sport=src_port,dport=dst_port,flags="S"),timeout=3,verbose=False)
		if(str(type(hst))=="<type 'NoneType'>"):
			print dst_port,"Filtered"
			tcp_filtered.append(dst_port)
		elif(hst.haslayer(TCP)):
			if(hst.getlayer(TCP).flags == 0x12):
				hst1=sr(IP(dst=str(add))/TCP(sport=src_port,dport=dst_port,flags="AR"),timeout=10,verbose=False)	
				#print dst_port,"Open"
				tcp_open.append(dst_port)
			elif (hst.getlayer(TCP).flags == 0x14):
				#print dst_port,"Closed"
				tcp_closed.append(dst_port)
		elif(hst.haslayer(ICMP)):
			if(int(hst.getlayer(ICMP).type)==3 and int(hst.getlayer(ICMP).code) in [1,2,3,9,10,13]):
				#print dst_port,"Filtered"
				tcp_filtered.append(dst_port)
def UDP_PACKET_ANALYSIS(add):
	for dst_port in xrange(1,101):
		if(dst_port == 25 or dst_port == 50 or dst_port == 75):
			print dst_port,"%","Done."
		src_port = RandShort()
		hst=sr1(IP(dst=str(add))/UDP(sport=src_port,dport=dst_port),timeout=3,verbose=False)
		if(str(type(hst))=="<type 'NoneType'>"):
			retrans = []
			for count in xrange(0,10):
				retrans.append(sr1(IP(dst=str(add))/UDP(sport=src_port,dport=dst_port),timeout=3,verbose=False))
			count=0
			for item in retrans:
				count+=1				
				if (str(type(item))!="<type 'NoneType'>"):
					if(item.haslayer(ICMP)):
						if(int(item.getlayer(ICMP).type)==3 and int(item.getlayer(ICMP).code)==3):
							udp_closed.append(dst_port)
							break
						elif(int(item.getlayer(ICMP).type)==3 and int(item.getlayer(ICMP).code) in [1,2,9,10,13]):
							udp_open_filtered.append(dst_port)
							break
				else:	
					hst = sr1(IP(dst=str(add))/UDP(sport=src_port, dport=dst_port)/DNS(),timeout=3,verbose=False)
					if(str(type(hst))!="<type 'NoneType'>"):
						udp_open.append(dst_port)
						break
					else:
						hst = sr1(IP(dst=str(add))/UDP(sport= 68,dport= dst_port)/BOOTP(chaddr="02:1d:07:00:00:f7", ciaddr = '0.0.0.0')/DHCP(options=[("message-type","discover"),"end"]),timeout = 10,verbose=False)
						if(str(type(hst))!="<type 'NoneType'>"):
							udp_open.append(dst_port)
							break
						else:	
							hst = sr1(IP(dst=str(add))/UDP(sport= 67, dport= dst_port)/BOOTP(chaddr="02:1d:07:00:00:f7", siaddr= "10.10.111.107", ciaddr = "10.10.111.1")/DHCP(options=[("message-type","offer"),("subnet_mask","255.255.255.0"),("server_id","10.10.111.107"),"end"]),timeout = 10,verbose=False)
							if(str(type(hst))!="<type 'NoneType'>"):
								udp_open.append(dst_port)
								break
							else:
								udp_open_filtered.append(dst_port)
								break
		elif (hst.haslayer(UDP)):
			udp_open.append(dst_port)
		elif(hst.haslayer(ICMP)):
			if(int(hst.getlayer(ICMP).type)==3 and int(hst.getlayer(ICMP).code)==3):
				udp_closed.append(dst_port)
			elif(int(hst.getlayer(ICMP).type)==3 and int(hst.getlayer(ICMP).code) in [1,2,9,10,13]):
				udp_open_filtered.append(dst_port)
def UDP_SERVICE_SEND():
	print "SENDING PACKETS: "	
	hst = sr1(IP(dst=str(add))/UDP(dport=53)/DNS(),timeout=3,verbose=False)
	print "DNS SENT..."	
	hst = sr1(IP(dst=str(add))/UDP(sport= 68,dport= 67)/BOOTP(chaddr="02:1d:07:00:00:f7", ciaddr = '0.0.0.0')/DHCP(options=[("message-type","discover"),"end"]),timeout = 10,verbose=False)
	print "DHCP DISCOVER SENT..."	
	hst = sr1(IP(dst=str(add))/UDP(sport= 67, dport= 68)/BOOTP(chaddr="02:1d:07:00:00:f5", siaddr= "10.10.111.107", ciaddr = "10.10.111.1")/DHCP(options=[("message-type","offer"),("subnet_mask","255.255.255.0"),("server_id","10.10.111.107"),"end"]),timeout = 10,verbose=False)
	print "DHCP OFFER SENT..."

def UDP_SERVICE_DISCOVERY():
	print "UDP SERVICES OPEN ARE:"
	udp_dict = dict((UDP_SERVICES[k], k) for k in UDP_SERVICES.keys())
	for i in udp_open:
		if i in udp_dict:
			print i," ",udp_dict[i]
		else:
			print i," ","N/A"

	for j in udp_open_filtered:		
		if j in udp_dict:
			print j," ",udp_dict[j]	
		else:
			print i," ","N/A"
	UDP_SERVICE_SEND()
	
print "TCP SCAN IN PROGRESS..."
TCP_PACKET_ANALYSIS(add)
print "TCP SCAN DONE..."

print "TCP OPEN PORTS:",len(tcp_open), "Ports open"
print tcp_open
print "TCP CLOSED PORTS:",len(tcp_closed), "Ports closed"
print tcp_closed
print "TCP FILTERED PORTS:",len(tcp_filtered), "Ports filtered"
print tcp_filtered

print "UDP SCAN IN PROGRESS..."
UDP_PACKET_ANALYSIS(add)
print "UDP SCAN DONE..."

print "UDP OPEN PORTS:",len(udp_open), "Ports open"
print udp_open
print "UDP CLOSED PORTS:",len(udp_closed), "Ports closed"
print udp_closed
print "UDP FILTERED PORTS:",len(udp_open_filtered), "Ports open or filtered"
print udp_open_filtered

UDP_SERVICE_DISCOVERY()
print "SCAN DONE!"
