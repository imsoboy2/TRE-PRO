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

parser = argparse.ArgumentParser(description='send packets')
parser.add_argument('--fname', required=True, default='', help='name of saved file')
parser.add_argument('--dist', required=False, default='z80_dist', help='flow distribution')
parser.add_argument('--pktnum', type=int, required=False, default=0, help='number of packets')

pktsum = 0

def make_packet(srcip, payload):
  ether = Ether(dst=get_if_hwaddr(dst_if))
  ip = IP(src=srcip, dst='10.10.0.200')
  udp = UDP(sport=6789, dport=1234)
  pkt = ether / ip / udp / payload
  return pkt

def main():
  a = parser.parse_args()

  global pktsum

  NUM_OF_PAYLOAD = int(a.pktnum)

  set_of_ip = []
  with open("build/" + a.dist + '_' + str(NUM_OF_PAYLOAD), 'r') as f:
    while True:
      line = f.readline()
      set_of_ip.append(line.strip())
      if not line: break

  set_of_ip.remove('')

  payload = ''
  ipcnt = 0

  plist = []
  with open("finefoods.txt", 'r') as f:
    for i in range(5000):
      cnt = 0
      plist.append([])
      for line in f:
        if cnt >= 1: break
        if line.strip():
          payload += line
        else:
          pkt = make_packet('10.0.0.1', payload)
          if len(pkt) > 600:
            payload = ''
            continue
          plist[i].append(payload)
          payload = ''
          cnt += 1

  f1 = open("build/results/retransmission/sentpkt_" + a.fname, "w")
  for i in range(len(set_of_ip)):
    idx = int(set_of_ip[i], 16) - 1
    classC = int(set_of_ip[i][0:2], 16)
    classD = int(set_of_ip[i][2:4], 16)
    srcip = '10.0.%d.%d' % (classC, classD)
    payload = plist[idx][0]
    pkt = make_packet(srcip, payload)
    pktsum += len(pkt)
    sendp(pkt, iface=dst_if, verbose=False)
    f1.write(str(pkt[Raw]) + '\n')
    ipcnt += 1
  f1.close()
  
  with open("build/results/reduction/sentsum_" + a.fname, "w") as f:
    f.write(str(pktsum) + "\n")

if __name__ == '__main__':
  main()
