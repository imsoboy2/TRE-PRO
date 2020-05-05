f1 = open("sentpkt", "r")

pset = set()
while True:
    payload = f1.readline()
    pset.add(payload)
    if not payload: break

f1.close()

f2 = open("recvpkt", "r")
diffcnt = 0
samecnt = 0
while True:
    line2 = f2.readline()
    if not line2: break # no more data, break
    if line2 in pset: samecnt += 1
    else:
        print 'diff!!!'
        print line2 
        diffcnt += 1

f2.close()

print "diff cnt = ", diffcnt
print "same cnt = ", samecnt