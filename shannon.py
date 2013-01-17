import math

# logarithm Base (default = 2)
LOG_BASE = 2 # math.e

def shannon(data):
   # We determine the frequency of each byte
   # in the dataset and if this frequency is not null we use it for the
   # entropy calculation
   dataSize = len(data)
   ent = 0.0
   
   freq={}   
   for c in data:
      if freq.has_key(c):
         freq[c] += 1
      else:
         freq[c] = 1

   # a byte can take 256 values from 0 to 255. Here we are looping 256 times
   # to determine if each possible value of a byte is in the dataset
   for key in freq.keys():
      f = float(freq[key])/dataSize
      if f > 0: # to avoid an error for log(0)
         ent = ent + f * math.log(f, LOG_BASE)

   return -ent
