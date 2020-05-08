import random
import scipy.stats as ss
import numpy as np

d_min = 1; d_max = 100; d_avg = (d_min + d_max) / 2
num_of_data = 10000

dist = input('[u]niform or [g]aussian or [z]ipf? : ')

n = []
if dist == 'u':
  for i in range(0, num_of_data):
    n.append(random.randint(d_min, d_max))

elif dist == 'g': 
  x = np.arange(d_min, d_max + 1) # np.arange(min, max)
  xU, xL = x + 0.5, x - 0.5 
  prob = ss.norm.cdf(xU, scale = 3, loc = d_avg) - ss.norm.cdf(xL, scale = 3, loc = d_avg)
  prob = prob / prob.sum() # normalize the probabilities so their sum is 1
  n = np.random.choice(x, size = num_of_data, p = prob)

elif dist == 'z':
  x = np.arange(d_min, d_max + 1)
  print(x)

  p = ss.zipf.pmf(x, a = 1.5)
  p /= p.sum()
  n = np.random.choice(x, size = num_of_data, p = p)

with open(dist + '_dist', 'w') as f:
  for i in range(0, num_of_data):
    f.write('10.10.0.' + str(n[i]) + '\n')

