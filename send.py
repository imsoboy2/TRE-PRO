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

def make_packet(payload):
	ether = Ether(src=get_if_hwaddr(src_if), dst=get_if_hwaddr(dst_if))
	ip = IP(dst='127.0.0.1')
	udp = UDP(dport=1234)
	custom_header = custom_hdr()
	pkt = ether / ip / udp / custom_header / payload
	return pkt
    
def main():
    a = parser.parse_args()

    iface = "enp0s3"

    range_bottom = 1
    range_top = 100000

    ether = Ether(src=a.sm, dst=a.dm)
    ip = IP(src=a.si, dst=a.di, proto=17) 
    udp = UDP(sport=a.sp, dport=a.dp)

    for num in range(0, 10000):
    	print('\n---------- Send pakcet ----------')
    	pkt = ether / ip / udp / '''product/productId: B001E4KFG0
review/userId: A3SGXH7AUHU8GW
review/profileName: delmartian
review/helpfulness: 1/1
review/score: 5.0
review/time: 1303862400
review/summary: Good Quality Dog Food
review/text: I have bought several of the Vitality canned dog food products and have
found them all to be of good quality. The product looks more like a stew than a
processed meat and it smells better. My Labrador is finicky and she appreciates this
product better than most.'''
    	pkt.show()
    	sendp(pkt, iface=iface, verbose=False)

if __name__ == '__main__':
    main()
