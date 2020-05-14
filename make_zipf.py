import random
import math

num_query = 100000
path_query = "z80_dist_" + str(num_query / 10)
zipf = 0.80

len_key = 16
len_val = 128
max_key = 4999

#Zipf
zeta = [0.0]
for i in range(1, max_key + 1):
    zeta.append(zeta[i - 1] + 1 / pow(i, zipf))
field = [0] * (num_query + 1)
k = 1
for i in range(1, num_query + 1):
    if (i > num_query * zeta[k] / zeta[max_key]):
        k = k + 1
    field[i] = k

del field[0]
print str(field)

with open(path_query, 'w') as f:
  for i in range(0, num_query):
    a = random.choice(field)
    num = "%04X" % a
    f.write(num + '\n')
    # classC = int(num[0:2], 16)
    # classD = int(num[2:4], 16)
    # f.write('10.10.%d.%d\n' % (classC, classD))