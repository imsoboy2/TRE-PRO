f1 = open("sentpkt", "r")
f2 = open("recvpkt", "r")

diffcnt = 0
samecnt = 0
while True:
    line1 = f1.readline()
    line2 = f2.readline()
    if not line2 or not line1: break # no more data, break
    if line1 == line2: samecnt += 1
    else: diffcnt += 1

f1.close()
f2.close()

print "diff cnt = ", diffcnt
print "same cnt = ", samecnt