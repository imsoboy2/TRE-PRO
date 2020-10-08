num_of_packets = [500, 1000, 5000, 10000, 20000]
dist_type = ["z80", "z60", "z40"]

print "-------- Reduction Ratio --------"
print "\tz80\tz60\tz40"
for num in num_of_packets:
    print str(num * 10) + "\t",
    for dtype in dist_type:
        recv = open("build/results/reduction/recvsum_dist" + dtype + "_pktnum" + str(num), "r")
        sent = open("build/results/reduction/sentsum_dist" + dtype + "_pktnum" + str(num), "r")

        rnum = recv.read().strip()
        snum = sent.read().strip()

        print "%.2f%%\t" % ((1.0 - (float(int(rnum)) / int(snum))) * 100),

        recv.close()
        sent.close()
    print ""