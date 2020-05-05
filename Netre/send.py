#!/usr/bin/env python
import argparse
import sys
import socket
import random
import struct
import time

from scapy.all import sendp, send, get_if_list, get_if_hwaddr, hexdump
from scapy.all import Packet
from scapy.all import Ether, IP, UDP, TCP
from scapy.all import hexdump, ShortField, BitField, BitFieldLenField, ShortEnumField, X3BytesField, ByteField, XByteField

parser = argparse.ArgumentParser(description='send entry packet')
parser.add_argument('--sm', required=False, default='00:00:00:00:00:01', help='source MAC address')
parser.add_argument('--dm', required=False, default='00:00:00:00:00:02', help='destination MAC address')
parser.add_argument('--si', required=False, default='10.0.0.1', help='source IP address')
parser.add_argument('--di', required=False, default='10.0.0.2', help='destination IP address')
parser.add_argument('--sp', required=False, type=int, default=1234, help='source PORT number')
parser.add_argument('--dp', required=False, type=int, default=5678, help='destination PORT number')
parser.add_argument('--key', required=False, type=int, default=1111, help='key')

class entry_hdr(Packet):
    """ Entry Header """
    name = "entry"
    fields_desc = [
        BitField('flush', 0, 8),
        BitField('key0', 0, 128),
        BitField('value0', 1, 32),
        BitField('key1', 0, 128),
        BitField('value1', 1, 32),
        BitField('key2', 0, 128),
        BitField('value2', 1, 32),
        BitField('key3', 0, 128),
        BitField('value3', 1, 32),
        BitField('key4', 0, 128),
        BitField('value4', 1, 32),
        BitField('key5', 0, 128),
        BitField('value5', 1, 32),
        BitField('key6', 0, 128),
        BitField('value6', 1, 32),
        BitField('key7', 0, 128),
        BitField('value7', 1, 32),
        BitField('key8', 0, 128),
        BitField('value8', 1, 32),
        BitField('key9', 0, 128),
        BitField('value9', 1, 32),
    ]

def main():
    a = parser.parse_args()

    iface = "veth1"

    range_bottom = 1
    range_top = 100000

    ether = Ether(src=a.sm, dst=a.dm)
    ip = IP(src=a.si, dst=a.di, proto=17) 
    udp = UDP(sport=a.sp, dport=a.dp)

    for num in range(0, 200):
    	print('\n---------- Send pakcet ----------')
    	pkt = ether / ip / udp / entry_hdr(flush=1)
    	pkt.show()
    	sendp(pkt, iface=iface, verbose=False)

if __name__ == '__main__':
    main()
