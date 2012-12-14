import math

# logarithm Base (default = 2)
LOG_BASE = 2 # math.e

# Here, we give 2 implementation of shannon entropy:
# - one using a simple loop
# - the second using an alphabet
# For small dataset, the second is much more efficient but with
# large amount of data, the first one must be more efficient.
# It could be interresting to make a benchmark on these functions

# Caculate shannon entropy of a set of data
def shannon_entropy (data):
    # Whithin the for statement, we determine the frequency of each byte
    # in the dataset and if this frequency is not null we use it for the
    # entropy calculation
    dataSize = len(data)
    ent = 0.0

    # a byte can take 256 values from 0 to 255. Here we are looping 256 times
    # to determine if each possible value of a byte is in the dataset
    for i in range(256):
        freq = float(data.count(i))/dataSize
        if freq > 0:    # to avoid an error for log(0)
            ent = ent + freq * math.log(freq, LOG_BASE)

    return -ent

# Caculate shannon entropy of a set of data using an alphabet
def shannon_entropy2 (data):
    # Here, instead of looping 256 times and determining if the byte is
    # in the dataset, we firstly determine the dataset alphabet (all
    # bytes that compose the dataset). The next step si like the above function
    dataSize = len(data)
    alphabet = list(set(data))
    ent = 0.0
    for c in alphabet:
        freq = float(data.count(c))/dataSize
        # here, no need to test if freq is > 0 cause if the byte is in
        # the alphabet, that's mean there are at least one of this byte
        # in the dataset
        ent = ent + freq * math.log(freq, LOG_BASE)

    return -ent

testList = list(bytearray("The concept was introduced by Claude E. Shannon in  the paper"))

print testList
print shannon_entropy(testList)
print shannon_entropy2(testList)
