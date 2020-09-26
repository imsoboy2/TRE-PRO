#!/usr/bin/env python
import argparse

parser = argparse.ArgumentParser(description='send packets')

parser.add_argument('--innum', required=True, type=int, default='', help='name of saved file')
# parser.add_argument('--pos', required=True, default='', help='name of saved file')
parser.add_argument('--pktnum', required=True, type=int, default='', help='name of saved file')
# parser.add_argument('--fname', required=True, default='', help='name of saved file')

a = parser.parse_args()
pset = set()
cnt = 0
for i in range(1, a.innum + 1):
    f1 = open("results/retransmission/sentpkt_in" + str(a.innum) + "_" + str(i) + "_pktnum" + str(a.pktnum), "r")

    payload = ''
    while True:
        line = f1.readline()
        if not line:
            print "cnt = ", cnt
            cnt = 0 
            break
        if line.strip():
            payload += line
        else:
            pset.add(payload)
            payload = ''
            cnt += 1
    print(len(pset))
    f1.close()

diffcnt = 0
samecnt = 0
pktcnt = 0
cnt = 0
# f2 = open("results/retransmission/recvpkt_in" + str(a.innum) + "_pktnum" + str(a.pktnum), "r")
# payload = ''
# pset2 = set()

# while True:
#     line = f2.readline()
#     if not line: break # no more data, break
#     if line.strip():
#         payload += line
#     else:
#         pktcnt += 1
#         if payload in pset: 
#             samecnt += 1
#         else:
#             # print '-----payload-----'
#             # print(payload)
#             # print '------------'
#             diffcnt += 1
#             # print cnt, 'th pkt'
#         payload = ''

# f2.close()
for i in range(0, 2):
    f2 = open("results/retransmission/recvpkt_in" + str(a.innum) + "_" + str(i) + "_pktnum" + str(a.pktnum), "r")
    payload = ''
    pset2 = set()

    while True:
        line = f2.readline()
        if not line:
            break # no more data, break
        if line.strip():
            payload += line
        else:
            pktcnt += 1
            if payload in pset: 
                samecnt += 1
            else:
                # print '-----payload-----'
                # print(payload)
                # print '------------'
                diffcnt += 1
                # print cnt, 'th pkt'
            payload = ''
    f2.close()

# print(len(pset))
# print(len(pset))
# print(len(pset2)) 
print "pktcnt = ", pktcnt
print "diff cnt = ", diffcnt
print "same cnt = ", samecnt
