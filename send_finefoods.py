#!/usr/bin/env python

import argparse
import sys
import socket
import random
import struct
import re
import time 

from scapy.all import sniff, sendp, send, srp1, get_if_list, get_if_hwaddr
from scapy.all import Packet, hexdump
from scapy.all import hexdump, BitField, BitFieldLenField, ShortEnumField, X3BytesField, ByteField, XByteField
from scapy.all import Ether, IP, UDP, TCP, Raw
from scapy.all import bind_layers
import readline

dst_if = 'veth1'

pktsum = 0
class custom_hdr(Packet):
    """Custom Header"""
    name = 'custom_hdr'
    fields_desc = [
        BitField('bitmap', 0, 10),
        BitField('dstIP', 0, 32),
        BitField('reserved', 0, 6)
    ]
bind_layers(UDP, custom_hdr)

def make_packet(srcip, payload):
  ether = Ether(dst=get_if_hwaddr(dst_if))
  ip = IP(src=srcip, dst='10.10.0.200')
  udp = UDP(sport=6789, dport=1234)
  pkt = ether / ip / udp / payload
  return pkt

NUM_OF_PAYLOAD = 5000
LOOP_CNT = 2
# the # of packets is NUM_OF_PAYLOAD * LOOP_CNT

def main():
  global pktsum
  set_of_ip = []
  with open('z_dist', 'r') as f:
    while True:
      line = f.readline()
      set_of_ip.append(line.strip())
      if not line: break
	
  print(len(set_of_ip))
  payload = ''
  ipcnt = 0
  with open("sentpkt", 'w') as f1:
    for i in range(0, LOOP_CNT):
      cnt = 0
      with open("finefoods.txt", 'r') as f:
        for line in f:
          if cnt >= NUM_OF_PAYLOAD: break
          if line.strip():
            payload += line
          else:
            pkt = make_packet(set_of_ip[ipcnt], payload)
            pktsum += len(pkt)
            sendp(pkt, iface=dst_if, verbose=False)
            if ipcnt <= NUM_OF_PAYLOAD: f1.write(str(pkt[Raw]) + '\n')
            payload = ''
            cnt += 1
            ipcnt += 1
            print("--- cnt: ", ipcnt)
            print(pktsum) 

if __name__ == '__main__':
  main()
