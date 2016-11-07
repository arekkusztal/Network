#!/usr/bin/python

from socket import *
import os, struct, sys

class IP:
	def __init__(self,  ip_v, ip_len)
		self.ip_v = ip_v
		self.ip_len = ip_len

source_ip = gethostbyname(gethostname()) #Tread me as locallhost
dest_ip = "192.168.1.1" #Arghhhh

upd_hdr_size = 8

if (os.geteuid() != 0):
	print "Root yourself"
	quit()

sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)

payload = "Isnt Python great?"

ip_ihl = 5
ip_ver = 4
ip_tos = 0 
ip_len = 0
ip_id = 0xFFAA
ip_fragoff = 0
ip_ttl = 64
ip_proto = 17
ip_check = 0
ip_saddr = inet_aton(source_ip) 
ip_daddr = inet_aton(dest_ip)
ip_ihlver = (ip_ver << 4) + ip_ihl

udp_sport = 1683
udp_dport = 1612
udp_len = upd_hdr_size + len(payload)
udp_chk = 0


ip_header = struct.pack('!BBHHHBBH4s4s' , ip_ihlver, ip_tos, ip_len, ip_id, ip_fragoff, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)
udp_header = struct.pack('!HHHH', udp_sport, udp_dport, udp_len, udp_chk)

packet = ip_header + udp_header + payload

sd.sendto(packet, (dest_ip, 0))
