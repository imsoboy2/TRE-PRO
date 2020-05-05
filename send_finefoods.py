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
def make_packet(srcip, payload):
  ether = Ether(dst=get_if_hwaddr(dst_if))
  ip = IP(src=srcip, dst='10.10.0.200')
  udp = UDP(sport=6789, dport=1234)
  pkt = ether / ip / udp / payload
  return pkt

def main():
  global pktsum
  set_of_ip = []
  with open('g_dist', 'r') as f:
    while True:
      line = f.readline()
      set_of_ip.append(line.strip())
      if not line: break
	
  print(len(set_of_ip))
  payload = ''
  ipcnt = 0
  with open("sentpkt", 'w') as f1:
    for i in range(0, 2):
      cnt = 0
      with open("finefoods.txt", 'r') as f:
        for line in f:
          if cnt >= 5000: break
          if line.strip():
            payload += line
          else:
            # print(payload)
            pkt = make_packet(set_of_ip[ipcnt], payload)
            pktsum += len(pkt)
            sendp(pkt, iface=dst_if, verbose=False)
            # hexdump(pkt)
            #print(str(pkt[IP].src) + str(pkt[Raw]) + '\n')
            # byte_array = map(ord, str(pkt[IP].src) + str(pkt[Raw]))
            if ipcnt <= 5000: f1.write(str(map(ord, str(pkt[Raw]))) + '\n')
            payload = ''
            cnt += 1
            ipcnt += 1
            print("--- cnt: ", cnt)
            print(pktsum) 

if __name__ == '__main__':
  main()
