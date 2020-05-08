#!/usr/bin/env python
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

pktsum = 0
def handle_pkt(pkt):
    global pktsum
    # pkt.show()
    hexdump(pkt)
    pktsum += len(pkt)
    print(pktsum)

def main():
    # interface = 'veth0'
    interface = 'veth3'
    ifaces = filter(lambda i: interface in i, os.listdir('/sys/class/net/'))
    iface = ifaces[0]
    print "sniffing on %s" % iface
    sys.stdout.flush()
    sniff(iface = interface,
        prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
