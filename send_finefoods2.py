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

dst_if = 'veth7'

parser = argparse.ArgumentParser(description='send packets')
parser.add_argument('--fname', required=True, default='', help='name of saved file')
parser.add_argument('--dist', required=False, default='z_dist', help='flow distribution')
parser.add_argument('--pktnum', type=int, required=False, default=0, help='number of packets')

pktsum = 0

def make_packet(srcip, payload):
  ether = Ether(dst=get_if_hwaddr(dst_if))
  ip = IP(src=srcip, dst='10.10.0.200')
  udp = UDP(sport=6789, dport=1234)
  pkt = ether / ip / udp / payload
  return pkt

NUM_OF_PAYLOAD = 5
LOOP_CNT = 10
# the # of packets is NUM_OF_PAYLOAD * LOOP_CNT

def main():
  a = parser.parse_args()

  global pktsum, NUM_OF_PAYLOAD, LOOP_CNT

  NUM_OF_PAYLOAD = int(a.pktnum)

  set_of_ip = []
  with open(a.dist + '2_' + str(NUM_OF_PAYLOAD), 'r') as f:
    while True:
      line = f.readline()
      set_of_ip.append(line.strip())
      if not line: break
	
  set_of_ip.remove('')
  print(len(set_of_ip))
  
  payload = ''
  ipcnt = 0

  plist = []
  flowcnt = []
  with open("finefoods2.txt", 'r') as f:
    for i in range(1000):
      flowcnt.append(0)
      cnt = 0
      plist.append([])
      for line in f:
        if cnt >= 1: break
        if line.strip():
          payload += line
        else:
          pkt = make_packet('10.0.0.1', payload)
          if len(pkt) > 1500:
            payload = ''
            continue
          plist[i].append(payload)
          payload = ''
          cnt += 1

  print(len(plist))
  print(len(flowcnt))

  f1 = open("results/retransmission/sentpkt_" + a.fname, "w")         
  for j in range(1):        
    for i in range(len(set_of_ip)):
      idx = int(set_of_ip[i], 16) - 1000
      classC = int(set_of_ip[i][0:2], 16)
      classD = int(set_of_ip[i][2:4], 16)
      srcip = '10.0.%d.%d' % (classC, classD)
      payload = plist[idx][flowcnt[idx]]
      pkt = make_packet(srcip, payload)
      pktsum += len(pkt)
      time.sleep(0.01)
      sendp(pkt, iface=dst_if, verbose=False)
      if j == 0: f1.write(str(pkt[Raw]) + '\n')
      flowcnt[idx] = (flowcnt[idx] + 1) % 1
      ipcnt += 1
  f1.close()

  with open("results/reduction/sentsum_" + a.fname, "w") as f:
    f.write("pktcnt = " + str(ipcnt) + "\n")
    f.write("pktsum = " + str(pktsum) + "\n")
    
if __name__ == '__main__':
  main()