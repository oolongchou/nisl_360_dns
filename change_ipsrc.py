import dpkt
import dns.message
import socket
import struct
import os
import sys
import random
import time

pcapf = sys.argv[1]  # 1.pcap
outputf = dpkt.pcap.Writer(open(pcapf.strip(".pcap") + '_scr_ip_change.pcap', 'wb'))
pcap = dpkt.pcap.Reader(open(pcapf, "rb"))

count = 0
for ts, buf in pcap:
    count += 1
    if count % 1000 == 0:
        print(count, "packets.")
    eth = dpkt.ethernet.Ethernet(buf)

    if(count % random.randrange(14,60)):
        rip = lambda: '.'.join(
            [str(int(''.join([str(random.randint(0, 2)), str(random.randint(0, 5)), str(random.randint(0, 5))])))
             for _ in range(4)])
        randomip = str(rip())
        eth.data.src = socket.inet_pton(socket.AF_INET, randomip)
        ts_new = time.time()
        outputf.writepkt(eth, ts_new)
    ts_new = time.time()
    outputf.writepkt(eth, ts_new)