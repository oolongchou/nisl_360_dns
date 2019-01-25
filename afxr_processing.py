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

# change the qname in the Message subject.
def change_qname(dns_msg, qname):
    new_name = dns.name.from_text(qname)
    dns_msg.question[0].name = new_name
    return dns_msg

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

def is_qtype(dns_msg, given_qtype):
    qtype_dic = {"AXFR": 252, "PTR": 12, "ANY":255,"TXT":16}
    try:
        qtype = dns_msg.question[0].rdtype
        if qtype == qtype_dic[given_qtype]:
            return True
    except Exception as e:
        return False
    return False



pcapf = "input_onequery.pcap"
outputf = dpkt.pcap.Writer(open(pcapf.strip(".pcap") + '_scr_ip_change.pcap', 'wb'))
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
        for qtype in ["AXFR"]:
            if is_qtype(dns_msg, qtype):
                if is_query_packet:
                    if (count % random.randrange(14, 60)):
                        rip = lambda: '.'.join(
                        [str(int(''.join([str(random.randint(0, 2)), str(random.randint(0, 5)), str(random.randint(0, 5))])))
                        for _ in range(4)])
                        randomip = str(rip())

                        # the new qname should be the same length as the original one (to avoid DNS/TCP packet length errors).
                        orgindomain = str(dns_msg.question[0].name).split(".")
                        len_subdomain = len(orgindomain[0])
                        randondomain= ''.join(random.choice(string.ascii_letters.lower() + string.digits) for i in range(len_subdomain))
                        randondomain=randondomain+"."+str(orgindomain[1])+"."+str(orgindomain[2])

                        # change the qname in the Message subject.
                        dns_msg_new = change_qname(dns_msg, randondomain)
                        eth.data.src = socket.inet_pton(socket.AF_INET, randomip)
                        # set the new DNS message in eth.data.data
                        set_dns_message(eth, dns_msg_new)
                        ts_new = time.time()
                        outputf.writepkt(eth, ts_new)

    except Exception as e:
        print(str(count) + "\t" + str(e))


