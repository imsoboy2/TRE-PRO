#!/usr/bin/env python

import argparse
import sys
import socket
import random
import struct
import re
import time
import copy

from scapy.all import sniff, sendp, send, srp1, get_if_list, get_if_hwaddr
from scapy.all import Packet, hexdump
from scapy.all import hexdump, BitField, BitFieldLenField, ShortEnumField, X3BytesField, ByteField, XByteField
from scapy.all import Ether, IP, UDP, TCP, Raw
from scapy.all import bind_layers
import readline

dst_if = 'eno7'

parser = argparse.ArgumentParser(description='send packets')
parser.add_argument('--fname', required=True, default='', help='name of saved file')
parser.add_argument('--dist', required=False, default='z80_dist', help='flow distribution')
parser.add_argument('--pktnum', type=int, required=False, default=0, help='number of packets')

pktsum = 0
def rabinHash(fp, prev, d, w):
  v = 0
  if len(d) == w: v = ord(d[-1])
  return (fp - (prev * (2 ** (w - 1)))) * 2 + v

def make_packet(srcip, payload):
  ether = Ether(dst=get_if_hwaddr(dst_if))
  ip = IP(src=srcip, dst='10.10.0.200')
  udp = UDP(sport=6789, dport=1234)
  pkt = ether / ip / udp / payload
  return pkt

NUM_OF_PAYLOAD = 5
LOOP_CNT = 10
# the # of packets is NUM_OF_PAYLOAD * LOOP_CNT

def find_fp(lst, fp):
  for i in range(len(lst)):
    if lst[i][0] == fp:
      return i
  return -1

def main():
  a = parser.parse_args()

  global pktsum, NUM_OF_PAYLOAD, LOOP_CNT

  NUM_OF_PAYLOAD = int(a.pktnum)

  set_of_ip = []
  with open(a.dist + '_' + str(NUM_OF_PAYLOAD), 'r') as f:
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

  w = 16
  p = 32
  dic = {}
  dic2 = {}
  lst = []

  f1 = open(a.fname, "w")
  start = time.time()
  print("start time = ", start)
  for j in range(1):
    for i in range(len(set_of_ip)):
    # for i in range(1):
      idx = int(set_of_ip[i], 16) - 1
      classC = int(set_of_ip[i][0:2], 16)
      classD = int(set_of_ip[i][2:4], 16)
      srcip = '10.0.%d.%d' % (classC, classD)
      payload = plist[idx][0]
      data = payload
      leng = len(data)
      # init
      fingerprint = 0
      for i in range(w):
        fingerprint = fingerprint * 2 + ord(data[i])
      prev = ord(data[0])
      encoded = data[0]
      cnt = i = 1
      # for i in range(1, leng - w + 1):
      # encoding
      while i < leng:
        if i < leng - w + 1:
          fingerprint = rabinHash(fingerprint, prev, data[i:i + w], w)
          if fingerprint % p == 0:
            # dictionary start
            if fingerprint not in dic or dic[fingerprint] != data[i:i + w]:
              dic[fingerprint] = copy.deepcopy(data[i:i+w])
              encoded += data[i:i+w]
            else:
              fp = "%08d" % fingerprint
              encoded += "#+" + str(fp)
            #   print(encoded)
            # dictionary end
            # list start
            # rtn = find_fp(lst, fingerprint)
            # if rtn != -1 and lst[rtn][1] == data[i:i+w]: # hit
            #   encoded += "@@@@"
            # else:
            #   if rtn != -1: # collision
            #     lst[rtn][1] = copy.deepcopy(data[i:i+w])
            #   else:
            #     lst.append([fingerprint, copy.deepcopy(data[i:i+w])])
            #   encoded += data[i:i+w]
            # list end
            fingerprint = 0
            i += w
            prev = ord(data[i - 1])
            fingerprint = 0
            for idx in range(w):
              if i + idx - 1 >= len(data): break
              fingerprint = fingerprint * 2 + ord(data[i + idx - 1])
            continue
        encoded += data[i]
        prev = ord(data[i])
        i += 1
      # init
      fingerprint = 0
      for i in range(w):
        fingerprint = fingerprint * 2 + ord(data[i])
      prev = ord(data[0])
      decoded = encoded
      cnt = i = 1
      # decoding
      fpidx = decoded.find("#+")
      if fpidx != -1:
          while fpidx != -1:
            dic2key = int(decoded[fpidx + 2:fpidx + 10])
            if dic2key in dic2:
              decoded = decoded[0:fpidx] + dic2[dic2key] + decoded[fpidx + 10:]
            else:
              decoded = decoded[0:fpidx] + decoded[fpidx + 10:]
            fpidx = decoded.find("#+")
      while i < leng:
        if i < leng - w + 1:
          fingerprint = rabinHash(fingerprint, prev, decoded[i:i + w], w)
          if fingerprint % p == 0:
            # dictionary start
            if fingerprint not in dic2 or dic2[fingerprint] != decoded[i:i + w]:
              dic2[fingerprint] = copy.deepcopy(decoded[i:i+w])
            # dictionary end
            fingerprint = 0

            i += w
            if i - 1 < len(decoded):
              prev = ord(decoded[i - 1])
            fingerprint = 0
            for idx in range(w):
              if i + idx - 1 >= len(decoded): break
              fingerprint = fingerprint * 2 + ord(decoded[i + idx - 1])
            continue
        if i < len(decoded):
          prev = ord(decoded[i])
        i += 1
      pkt = make_packet(srcip, encoded)
      decoded = make_packet(srcip, decoded)
      originpkt = make_packet(srcip, payload)
      pktsum += len(originpkt)
      # pkt.show()
      #sendp(pkt, iface=dst_if, verbose=False)
      f1.write(str(pkt[Raw]) + '\n')
      ipcnt += 1
  print(time.time() - start)
  f1.close()


  with open("sentsum_" + a.fname, "w") as f:
    f.write("pktcnt = " + str(ipcnt) + "\n")
    f.write("pktsum = " + str(pktsum) + "\n")

if __name__ == '__main__':
  main()
