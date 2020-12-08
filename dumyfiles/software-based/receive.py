#!/usr/bin/env python
import argparse
import sys
import struct
import os

from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr, bind_layers
from scapy.all import Packet, IPOption
from scapy.all import ShortField, IntField, LongField, BitField, FieldListField, FieldLenField
from scapy.all import IP, TCP, UDP, Raw, Ether, Padding
from scapy.layers.inet import _IPOption_HDR

class custom_hdr(Packet):
    """Custom Header"""
    name = 'custom_hdr'
    fields_desc = [
        BitField('bitmap', 0, 10),
        BitField('dstIP', 0, 32),
        BitField('reserved', 0, 6)
    ]

IPV4_PROTOCOL_TCP = 6
IPV4_PROTOCOL_UDP = 17

parser = argparse.ArgumentParser(description='send packets')
parser.add_argument('--fname', required=True, default='', help='name of saved file')

pktcnt = 0
pktsum = 0
fname = ''
latency_sum = 0
def handle_pkt(pkt):
    global pktsum, pktcnt, latency_sum
    if not (pkt.haslayer(UDP) and pkt[UDP].sport == 6789): return

    pktcnt += 1
    # pktdump(pkt)
    # hexdump(pkt)
    # print(pkt[Ether].dst)
    # print(pkt[Ether].src)
    dst_addr = pkt[Ether].dst.split(":")
    src_addr = pkt[Ether].src.split(":")

    dst = 0
    for num in dst_addr:
        dst *= 256
        dst += int(num, 16)
    src = 0
    for num in src_addr:
        src *= 256
        src += int(num, 16)
    # print(dst)
    # print(src)
    latency_sum += (src - dst)
    print(latency_sum / pktcnt)



    with open("results/reduction/recvsum_" + fname, "w") as f:
        f.write("pktcnt = " + str(pktcnt) + "\n")
        f.write("pktsum = " + str(pktsum) + "\n")
        f.write("end time = " + str(time.time()) + "\n")

    # hexdump(pkt)
    pktsum += len(pkt)

def main():
    global fname
    a = parser.parse_args()
    fname = a.fname

    # interface = 'veth0'
    interface = 'eno7'
    ifaces = filter(lambda i: interface in i, os.listdir('/sys/class/net/'))
    iface = ifaces[0]
    print "sniffing on %s" % iface
    sys.stdout.flush()
    sniff(iface = interface,
        prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
