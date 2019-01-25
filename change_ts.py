import dpkt
import dns.message
import socket
import struct
import os
import sys
import time

pcapf = sys.argv[1]  # 1.pcap
outputf = dpkt.pcap.Writer(open(pcapf.strip(".pcap") + '_ts_changed.pcap', 'wb'))
pcap = dpkt.pcap.Reader(open(pcapf, "rb"))

count = 0
for ts, buf in pcap:
    count += 1
    if count % 10000 == 0:
        print(count, "packets.")

    ts_new = time.time()
    outputf.writepkt(buf, ts_new)
