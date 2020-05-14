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
bind_layers(UDP, custom_hdr)

IPV4_PROTOCOL_TCP = 6
IPV4_PROTOCOL_UDP = 17

parser = argparse.ArgumentParser(description='send packets')
parser.add_argument('--fname', required=True, default='', help='name of saved file')

pktcnt = 0
pktsum = 0
fname = ''
def handle_pkt(pkt):
    global pktsum, pktcnt
    # pkt.show()

    with open("results/reduction/recvsum_" + fname, "w") as f:
        f.write("pktcnt = " + str(pktcnt) + "\n")
        f.write("pktsum = " + str(pktsum) + "\n")

    # hexdump(pkt)
    pktsum += len(pkt)
    pktcnt += 1
    # print(pktsum)

def main():
    global fname
    a = parser.parse_args()
    fname = a.fname

    interface = ['veth3', 'veth9']
    print "sniffing on %s" % interface
    sys.stdout.flush()
    sniff(iface = interface,
        prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()