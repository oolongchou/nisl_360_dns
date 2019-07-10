#!/usr/bin/python
# coding: utf-8

# insert the attack traffic into bkgd traffic.
# for each attack pcap, choose a random start time and insert it.

import dpkt
import sys
import os
import random

def set_start(bkgd_pcap, attack_pcap):
    # choose a random start time for attack pcap.
    # the start time should be larger than that of bkgd pcap, but smaller than the end of bkgd pcap (not sure if we can do that).
    bkgd_start = 0
    bkgd_end = 0

    # get the time of first packet.
    pcapf = dpkt.pcap.Reader(open(bkgd_pcap, "rb"))
    first_pkt = pcapf.__next__()
    bkgd_start = first_pkt[0]

    pcapf = dpkt.pcap.Reader(open(attack_pcap, "rb"))
    first_pkt = pcapf.__next__()
    attack_start = first_pkt[0]

    # generate a random int, and add it to bkgd_start.
    attack_start_new = bkgd_start + random.random() * BKGD_SPAN

    print "bkgd start: ", bkgd_start
    print "attack start:", attack_start
    print "new attack start: ", attack_start_new
    return attack_start_new - attack_start
    # return attack_start, attack_start_new


def merge_pcap(bkgd_pcap, attack_pcap, attack_diff):
    # mix bkgd_pcap and attack_pcap together.
    pcap_w = dpkt.pcap.Writer(open(bkgd_pcap.split(".pcap")[0] + "_" + attack_pcap.split(".pcap")[0] + ".pcap", "wb"))

    bkgd_pcapf = dpkt.pcap.Reader(open(bkgd_pcap, "rb"))
    attack_pcapf = dpkt.pcap.Reader(open(attack_pcap, "rb"))

    b = 1
    a = 1
    current_bkgd = bkgd_pcapf.__next__()
    current_attack = attack_pcapf.__next__()

    # write the smaller one, and get its next.
    while current_bkgd and current_attack:
        ts_bkgd = current_bkgd[0]
        ts_attack = current_attack[0] + attack_diff         # the modified attack ts

        if ts_bkgd < ts_attack:
            pcap_w.writepkt(current_bkgd[1], ts_bkgd)
            try:
                current_bkgd = bkgd_pcapf.__next__()
                b += 1
            except:
                current_bkgd = None
        else:
            pcap_w.writepkt(current_attack[1], ts_attack)
            try:
                current_attack = attack_pcapf.__next__()
                a += 1
            except:
                current_attack = None

        if (a + b) % 1000 == 0:
            print "attack: ", a, "bkgd: ", b

    # write the remaining packets.
    while current_bkgd:
        pcap_w.writepkt(current_bkgd[1], current_bkgd[0])
        try:
            current_bkgd = bkgd_pcapf.__next__()
            b += 1
        except:
            current_bkgd = None
        if (a + b) % 1000 == 0:
            print "attack: ", a, "\tbkgd: ", b
    while current_attack:
        pcap_w.writepkt(current_attack[1], current_attack[0] + attack_diff)
        try:
            current_attack = attack_pcapf.__next__()
            a += 1
        except:
            current_attack = None
        if (a + b) % 1000 == 0:
            print "attack: ", a, "bkgd: ", b


bkgd_pcap = "demo.pcap" # sys.argv[1]
attack_pcap = "demo1.pcap" # sys.argv[2]
###### IMPORTANT!! the time span of bkgd traffic (default: 1 day).
# BKGD_SPAN = 3600 * 24     # (24 hours)
BKGD_SPAN = 2.3 # sys.argv[3]


attack_diff = set_start(bkgd_pcap, attack_pcap)
#merge_pcap(bkgd_pcap, attack_pcap, attack_diff)