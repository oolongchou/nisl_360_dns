import dpkt
import dns.message
import dns.name
import socket
import struct
import os
import sys
import random
import time
import string


def get_dns_message(ip):
    if isinstance(ip.data, dpkt.tcp.TCP):
        return ip.data.data[2:]
    else:
        return ip.data.data

# modify the DNS packet in the eth packet.
def set_dns_message(eth, dns_msg):
    if isinstance(eth.data.data, dpkt.tcp.TCP):
        eth.data.data.data = eth.data.data.data[:2] + dns_msg.to_wire()
    else:
        eth.data.data.data = dns_msg.to_wire()

def is_query(flags):
    query = (flags & 0x8000) >> 15
    return query == 0


list=[]
dgalist = open('dga.txt','r')
dgalist = (dgalist.readlines())[18:]
outfile=open("check_dga.txt","w")

for dga in dgalist :
	list.append(dga.split('\t')[1])
data = set(list)

pcapf = "../data/1_white_dns.pcap"
pcap = dpkt.pcap.Reader(open(pcapf, "rb"))

count = 0
for ts, buf in pcap:
    count += 1
    if count % 1000 == 0:
        print(count, "packets.")
    try:
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        ip_src = socket.inet_ntoa(ip.src)
        ip_dst = socket.inet_ntoa(ip.dst)

        wire_dns = get_dns_message(ip)

        is_update_packet = False
        is_query_packet = False

        (message_id, message_flags, qcount, ancount,
         aucount, adcount) = struct.unpack('!HHHHHH', wire_dns[:12])
        #### 0. is this a query or response?
        if is_query(message_flags):
            is_query_packet = True
        dns_msg = dns.message.from_wire(wire_dns)
        orgindomain = str(dns_msg.question[0].name)[:-1]

        if orgindomain in data:
            print(orgindomain)
            outfile.write(orgindomain+"\n")
            print("DGA FIND!")


    except Exception as e:
        # print(str(count) + "\t" + str(e))
        continue

