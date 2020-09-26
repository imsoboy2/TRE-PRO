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
parser.add_argument('--si', required=False, default='10.0.10.1', help='source IP address')
parser.add_argument('--di', required=False, default='10.0.10.2', help='destination IP address')
parser.add_argument('--sp', required=False, type=int, default=1234, help='source PORT number')
parser.add_argument('--dp', required=False, type=int, default=5678, help='destination PORT number')
parser.add_argument('--key', required=False, type=int, default=1111, help='key')
    
def main():
    a = parser.parse_args()

    iface = "veth19"

    ether = Ether(src=a.sm, dst=a.dm)
    ip = IP(src=a.si, dst=a.di, proto=17) 
    udp = UDP(sport=a.sp, dport=a.dp)

    plist = []; payload = ''
    with open("test.txt", 'r') as f:
        for i in range(5):
            for line in f:
                if line.strip():
                    payload += line
                else:
                    if len(payload) > 1000:
                        payload = ''
                        continue
                    plist.append(payload)
                    payload = ''

    for i in range(0, 1):
        for num in range(0, 1):
       	    print('\n---------- Send pakcet ----------')
      	    pkt = ether / ip / udp / plist[num]
    	    # pkt.show()
            sendp(pkt, iface=iface, verbose=False)
            print(len(pkt))

if __name__ == '__main__':
    main()
