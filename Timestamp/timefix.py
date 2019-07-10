#!/usr/bin/python
# coding: utf-8

# parse the captured packets
# filter the packets, and leave only DNS packets (parse as DNS && port 53).
# filter the qnames, remove anything deeper than SLD.
# adjust the time of each DGA sample.

import dpkt
import socket
import sys
import os
from domain_parser import *
import random



### TIMESTAMP ADJUSTMENT
# if true, select a random time in bkgd traffic as start of each DGA sample.
adjust_time = True
bkgd_begin = 1549030240          # first pkt in bgkd traffic (UNIX TIMESTAMP)
bkgd_end = 1549076518        # last pkt in bkgd traffic (UNIX TIMESTAMP)

def get_start(root, filename):
    # get the start of this sample.
    pcapf = open(os.path.join(root, filename), "rb")
    pcap = dpkt.pcap.Reader(pcapf)
    return pcap.__next__()[0]

def get_delta(start):
    # calc the delta to be made.
    new = bkgd_begin + (bkgd_end - bkgd_begin) * random.random()
    return new - start

def process_thread(root, filename):
    pcapf = open(os.path.join(root, filename), "rb")
    pcap_w = dpkt.pcap.Writer(open(os.path.join(root, "result_" + filename), "wb"))

    delta = 0
    # get start time of this DGA sample.
    if adjust_time:
        dga_start = get_start(root, filename)
        delta = get_delta(dga_start)

    pcap = dpkt.pcap.Reader(pcapf)
    count = 0
    for ts, buf in pcap:
        count += 1
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            try:  
                pcap_w.writepkt(buf, ts + delta)
            except Exception as e:
                # print "[2]", count, e
                continue

        except Exception as e:
            # print "[1]", count, e
            pass

    pcapf.close()

for (root, dirs, files) in os.walk("."):
    for filename in files:
        print os.path.join(root, filename)
        if filename.endswith(".pcap") and not filename.startswith("result"):
            process_thread(root, filename)