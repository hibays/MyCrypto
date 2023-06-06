# Some integer hash functions

# input any bits; output 32 bits
def BKDRHash(n) :
	h = 0
	p = 131 # 31 131 1313 13131 131313 etc...
	while n :
		h = h*p + (n & 0xff)
		n >>= 8
	return h & 0xffffffff

# input any bits; output 32 bits
def SDBMHash(n) :
	h = 0
	while n :
		#h = (n & 0xff) + 65599*h
		h = (n & 0xff) + (h << 6) + (h << 16) - h;
		n >>= 8
	return h & 0xffffffff

# input any bits; output 32 bits
def APHash(n) :
	h = 0xAAAAAAAA
	while n :
		h ^= (hash >> 3)*(n & 0xff) ^ (hash << 7)
		n >>= 8
		if not n : continue
		h ^= ~((hash << 11)+(n & 0xff) ^ (hash >> 5))
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
	
# input any bits; output 32 bits
def DJBHash(n) :
	h = 5381
	while n :
		h += (h << 5) + (n & 0xff)
		n >>= 8
	return h & 0xffffffff
