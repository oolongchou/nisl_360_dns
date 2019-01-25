import dpkt
import dns.message
import dns.name
import os
import sys

__all__ = os.listdir(".")

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





dga = sys.argv[1]
dgadomain=open(dga,'r')
list=[]
for domain in dgadomain :
	list.append(domain.strip())
data = set(list)
outfile=open(str(str(dga).split(".")[0])+"dga_sample.txt","w")


for filename in __all__:
    if filename.endswith(".cap"):
        print(filename)
        pcap = dpkt.pcap.Reader(open(filename , "rb"))
        count = 0
        for ts, buf in pcap:
            count += 1
            if count % 1000 == 0:
                print(count, "packets.")
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                ip = eth.data

                wire_dns = get_dns_message(ip)


                dns_msg = dns.message.from_wire(wire_dns)

                #### 0. is this a query or response?


                # the new qname should be the same length as the original one (to avoid DNS/TCP packet length errors).
                orgindomain = str(dns_msg.question[0].name).rstrip(".")
                if orgindomain in list:
                    #print(orgindomain)
                    outfile.write(filename+"\t"+orgindomain + "\n")


            except Exception as e:
                continue







