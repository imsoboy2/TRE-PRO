#!/usr/bin/env python
import sys
import struct
import os

from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr, bind_layers
from scapy.all import Packet, IPOption
from scapy.all import ShortField, IntField, LongField, BitField, FieldListField, FieldLenField
from scapy.all import IP, TCP, UDP, Raw, Ether, Padding
from scapy.layers.inet import _IPOption_HDR

IPV4_PROTOCOL_TCP = 6
IPV4_PROTOCOL_UDP = 17

# class custom_hdr(Packet):
#     """Custom Header"""
#     name = 'custom_hdr'
#     fields_desc = [
#         BitField('bitmap', 0, 10),
#         BitField('dstIP', 0, 32),
#         BitField('reserved', 0, 6)
#     ]
# bind_layers(UDP, custom_hdr)

sum = 0

def handle_pkt(pkt):
    # print(str(pkt[IP].src) + str(pkt[Raw]) + '\n')
    with open("recvpkt", 'a') as f1:
        byte_array = map(ord, str(pkt[IP].src) + str(pkt[Raw]))
        f1.write(str(byte_array) + '\n')
    global sum
    sum += len(pkt)
    print 'sum : ', sum
    # pkt.show()
    #hexdump(pkt)

def main():
    interface = 'veth5'
    ifaces = filter(lambda i: interface in i, os.listdir('/sys/class/net/'))
    iface = ifaces[0]
    print "sniffing on %s" % iface
    sys.stdout.flush()
    sniff(iface = interface,
        prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
