# Some integer hash functions
from math import ceil

# input any bits; output 32 bits
def MurmurHash2(n, seed=0x5bd1e995) :
	# 'm' and 'r' are mixing constants generated offline.
	# They're not really 'magic', they just happen to work well.
	m = 0x5bd1e995
	r = 24
 
	# Initialize the hash to a 'random' value
	h = seed ^ ceil(n.bit_length() / 8)
 
	# Mix 4 bytes at a time into the hash
	while n :
		k = n & 0xffffffff
		
		k *= m
		k ^= k >> r
		k *= m
 
		h *= m
		h ^= k
 
		n >>= 0xffffffff
 
	# Handle the last few bytes of the input array
	if n >> 24 :
		... # pass
	elif n >> 16 :
		h ^= n & 0xff0000
	elif n >> 8 :
		h ^= n & 0xff00
	elif n :
		h ^= n; h *= m
	
	# Do a few final mixes of the hash to ensure the last few
	# bytes are well-incorporated.
	h ^= h >> 13;
	h *= m;
	h ^= h >> 15;
 
	return h & 0xffffffff
	
# input any bits; output 32 bits
def DJBHash(n) :
	h = 5381
	while n :
		h += (h << 5) + (n & 0xff)
		n >>= 8
	return h & 0xffffffff

# input any bits; output 32 bits
def BKDRHash(n) :
	h = 0
	p = 1313 # 31 131 1313 13131 131313 etc...
	while n :
		h = h*p + (n & 0xff)
		#h = (h << 10) + (h << 8) + (h << 5) + h + (n & 0xff)
		n >>= 8
	return h & 0xffffffff

# input any bits; output 32 bits
def SDBMHash(n) :
	h = 0
	while n :
		#h = (n & 0xff) + 65599*h
		h = (n & 0xff) + (h << 6) + (h << 16) - h
		n >>= 8
	return h & 0xffffffff

# input any bits; output 32 bits
def APHash(n) :
	h = 0xAAAAAAAA
	while n :
		h ^= (h >> 3)*(n & 0xff) ^ (h << 7)
		n >>= 8
		if not n : continue
		h ^= ~((h << 11)+(n & 0xff) ^ (h >> 5))
		n >>= 8
	return h & 0xffffffff

# input any bits; output 32 bits
def JSHash(n) :
	h = 1315423911 # nearly a prime - 1315423911 = 3 * 438474637
	while n :
		h ^= (h << 5) + (n & 0xff) + (h >> 2)
		n >>= 8
	return h & 0xffffffff
	
# input any bits; output 32 bits
def RSHash(n) :
	h = 0
	a, b = 63689, 378551
	while n :
		h = h*a + (n & 0xff)
		a *= b
		n >>= 8
	return h & 0xffffffff
	
# input 32 bits; output 32 bits
def wang_hash(seed) :
	seed = (seed ^ 61) ^ (seed >> 16)
	seed *= 9
	seed ^= seed >> 4
	seed *= 0x27d4eb2d
	seed &= 0xffffffff # *Just for Python's large int*
	seed ^= seed >> 15
	return seed & 0xffffffff

# input 64 bits; output 64 bits
def hash64shift(n) :
	n = ~n + (n << 21)
	n ^= n >> 24
	n += (n << 3) + (n << 8) # *=265
	n ^= n >> 14
	n += (n << 2) + (n << 4) # *=21
	n ^= n >> 28
	n += n << 31
	return n & 0xffffffffffffffff
	
# input 64 bits; output 32 bits
def hash64_32shift(n) :
	n = ~n + (n << 18)
	n ^= n >> 31
	n *= 21
	n ^= n >> 11
	n += n << 6
	n ^= n >> 22
	return n & 0xffffffff
