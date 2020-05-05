f2 = open("recvpkt", "r")

diffcnt = 0
samecnt = 0
while True:
    line2 = f2.readline()
    if not line2: break # no more data, break
    with open('sentpkt', 'r') as f1:
        while True:
            line1 = f1.readline()
            if not line1: 
                diffcnt += 1
                break
            if line1 == line2:
                samecnt += 1
                break

f2.close()

print "diff cnt = ", diffcnt
print "same cnt = ", samecnt