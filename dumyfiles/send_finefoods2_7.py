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

dst_if = ['veth5']

parser = argparse.ArgumentParser(description='send packets')
parser.add_argument('--fname', required=True, default='', help='name of saved file')
parser.add_argument('--dist', required=False, default='z80_dist', help='flow distribution')
parser.add_argument('--pktnum', type=int, required=True, default=0, help='number of packets')
parser.add_argument('--ing', type=int, required=True, default=2, help='number of ingress switch')

pktsum = 0

def make_packet(dstip, payload):
  ether = Ether(dst=get_if_hwaddr('veth5'))
  ip = IP(src='10.10.0.200', dst=dstip)
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
  switchnum = a.ing

  set_of_ip = []
  print 'opened file = ' + a.dist + '_' + str(NUM_OF_PAYLOAD / switchnum)
  with open(a.dist + '_' + str(NUM_OF_PAYLOAD / switchnum), 'r') as f:
    while True:
      line = f.readline()
      set_of_ip.append(line.strip())
      if not line: break
	
  set_of_ip.remove('')
  
  payload = ''
  ipcnt = 0

  plist = []
  with open("finefoods.txt", 'r') as f:
    for i in range(5000 * switchnum):
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
  
  print len(set_of_ip) # pktnum / switchnum
  f1 = open("results/retransmission/sentpkt_" + a.fname, "w")         
  for j in range(6, 7):        
    for i in range(len(set_of_ip)):
      idx = int(set_of_ip[i], 16) + 5000 * j - 1
      nthflow = "%04X" % (idx + 1) # another payload per srcip
      classC = int(nthflow[0:2], 16)
      classD = int(nthflow[2:4], 16)
      srcip = '10.0.%d.%d' % (classC, classD)
      print srcip, idx
      payload = plist[idx][0]
      pkt = make_packet(srcip, payload)
      pktsum += len(pkt)
      time.sleep(0.2)
      sendp(pkt, iface=dst_if[0], verbose=False)
      f1.write(str(pkt[Raw]) + '\n')
      ipcnt += 1
  f1.close()

  with open("results/reduction/sentsum_" + a.fname, "w") as f:
    f.write("pktcnt = " + str(ipcnt) + "\n")
    f.write("pktsum = " + str(pktsum) + "\n")
    
if __name__ == '__main__':
  main()