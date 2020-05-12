f1 = open("results/retransmission/sentpkt_perpair1", "r")

pset = set()
payload = ''
while True:
    line = f1.readline()
    if not line: break
    if line.strip():
        payload += line
    else:
        pset.add(payload)
        payload = ''

f1.close()
print(len(pset))
f1 = open("results/retransmission/sentpkt_perpair2", "r")

payload = ''
while True:
    line = f1.readline()
    if not line: break
    if line.strip():
        payload += line
    else:
        pset.add(payload)
        payload = ''

f1.close()

f2 = open("results/retransmission/recvpkt", "r")
diffcnt = 0
samecnt = 0
pktcnt = 0
cnt = 0
payload = ''
pset2 = set()
while True:
    line = f2.readline()
    if not line: break # no more data, break
    if line.strip():
        payload += line
    else:
        pktcnt += 1
        if payload in pset: 
            samecnt += 1
        else:
            print '-----payload-----'
            print(payload)
            print '------------'
            diffcnt += 1
            print cnt, 'th pkt'
        cnt += 1
        pset2.add(payload)
        payload = ''

f2.close()

# print(len(pset))
print(len(pset))
print(len(pset2)) 
print "pktcnt = ", pktcnt
print "diff cnt = ", diffcnt
print "same cnt = ", samecnt
