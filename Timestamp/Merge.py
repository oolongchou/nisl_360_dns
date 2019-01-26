from scapy.all import *
import sys

Usage = """
Usage: timestamp_fix.py [input1] [input2] [output] [base]

Merge two pcap files by timestamp. The input2 will be merged from base timestamp(with respect to input1 timestamp).

If base equals to -1, then input2 will be merged from the first timestamp of input1.
"""

DEBUG = True


def merge_packets(input1, input2, base):
    print("Reading pcaps...")
    set1 = rdpcap(input1)
    set2 = rdpcap(input2)
    if DEBUG:
        ts1 = [pkt.time for pkt in set1]
        ts2 = [pkt.time for pkt in set2]
        plt.plot(ts1)
        plt.show()
        plt.plot(ts2)
        plt.show()
    if base is None:
        tp = set2[0].time - set1[0].time
    else:
        tp = set2[0].time - base
    for pkt in set2:
        pkt.time = pkt.time - tp
    i = 0
    j = 0
    l1 = len(set1)
    l2 = len(set2)
    result = PacketList()
    print("Merging...")
    while i < l1 and j < l2:
        if set1[i].time <= set2[j].time:
            result.append(set1[i])
            i = i + 1
        elif set1[i].time > set2[j].time:
            result.append(set2[j])
            j = j + 1
    while i < l1:
        result.append(set1[i])
        i = i + 1
    while j < l2:
        result.append(set2[j])
        j = j + 1
    return result


if __name__ == "__main__":
    if len(sys.argv) != 5:
        print(Usage)
        exit(0)
    input1 = sys.argv[1]
    input2 = sys.argv[2]
    output = sys.argv[3]
    if sys.argv[4] != "-1":
        base = float(sys.argv[4])
    else:
        base = None
    merged = merge_packets(input1, input2, base)
    wrpcap(output, merged)
    print("Done!")
