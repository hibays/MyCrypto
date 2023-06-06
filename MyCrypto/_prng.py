# Pseudo-random Number Generator
from array import array

# Xorshift RNGs
# See https://gist.github.com/AbsoluteVirtue/82a1913196fe0922262930ee81c327cb
def Xorshift32(n) :
	# Algorithm "xor" from p. 4 of Marsaglia, "Xorshift RNGs"
	n ^= n << 13; n ^= n >> 17; n ^= n << 5
	return n
	
def Xorshift64(n) :
	# Algorithm "xor" from p. 5 of Marsaglia, "Xorshift RNGs"
	n ^= n << 13; n ^= n >> 7; n ^= n << 17
	return n

def _nn(n) :
	res = 0
	t = n
	while t :
		if t & 1 :
			res ^= n
		t >>= 1
		n <<= 1
	return res & 0xffffffffffffffff

def Xorshift64h(n) :
	# Algorithm "xor" from p. 5 of Marsaglia, "Xorshift RNGs"
	n ^= n << 13; n ^= n >> 7; n ^= n << 17
	# Add a hash function into result
	# power 2 then only keep middle 64 bits
	# prime bin: 107/43, 101/37, 83/19, 71/7, 67/3
	return (n*n >> 37) & 0xffffffffffffffff
	
def Xorshift64s(n) :
	# Xorshift64s, variant A_1(12,25,27) with multiplier M_32 from line 3 of table 5
	n ^= n << 12; n ^= n >> 25; n ^= n << 27
	return n * 0x2545f4914f6cdd1d
	
def Xorshift128(n) :
	for i in range(4) :
		t = n & 0xffffffff
		n >>= 32
		
		t ^= t << 11 & 0xffffffff
		t ^= t >> 8
		t ^= n >> 64 ^ n >> 83
		
		n |= t << 96
	return n


class Xorshift128p(object) :
	__slots__ = ('seed',)

	def __new__(cls, seed=12786985) :
		self = super().__new__(cls)
		self.seed = seed
		return self

	def __iter__(self) :
		t = self.seed
		while True :
			s = t & 0xffffffffffffffff
			t >>= 64
			
			t ^= t << 23 & 0xffffffffffffffff
			t ^= t >> 17
			t ^= s ^ s >> 26
			
			t |= s << 64
			self.seed = t
			
			yield t + s & 0xffffffffffffffff

	def __bytes__(self) :
		ra = array('Q', map(lambda i,j: j, range(2), self))
		ra = ra.tobytes()
		return ra
		return self.seed.to_bytes(16, 'big')
		
	def __int__(self) :
		return int.from_bytes(bytes(self), 'big')
	
	
class Xorshift1024s(object) :
	__slots__ = ('state', 'index')

	def __new__(cls, state=range(16)) :
		self = super().__new__(cls)
		self.state = array('Q', state)
		self.index = 0
		return self
	
	def __iter__(self) :
		state = self.state
		while True :
			s = state[self.index]
			self.index = (self.index + 1) & 15
			t = state[self.index]
			
			t ^= t << 31 & 0xffffffffffffffff
			t ^= t >> 11
			t ^= s ^ s >> 30
			
			state[self.index] = t
			
			yield t * 1181783497276652981 & 0xffffffffffffffff
	
	def __bytes__(self) :
		ra = array('Q', map(lambda i,j: j, range(16), self))
		ra = ra.tobytes()
		return self.state.tobytes()
		
# ISAAC RNG
# See https://eprint.iacr.org/2006/438.pdf
# Also https://rosettacode.org/wiki/The_ISAAC_cipher
def isaac(a, b, c, s) :
	def mix(a, i) :
		i &= 3
		if   i == 3 : i = a >> 16
		elif i == 2 : i = a << 2
		elif i == 1 : i = a >> 6
		else        : i = a << 13
		return a ^ i
	
	c += 1
	b += c
	o = [None]*256
	for i in range(256) :
		x = s[i]
		a = mix(a, i) + s[i+128 & 255]
		s[i] = y = a + b + s[s[i]>>2 & 255]
		o[i] = b = x + s[y>>10 & 255]
	
	return o

# MT19937 -> 32 bits
def mt19937(seed) :
	mt = [seed]*624
	for i in range(1, 624) :
		mt[i] = 1812433253 * (mt[i-1] ^ (mt[i-1] >> 30)) + i
	
	lower_mask = (1 << 31) - 1
	upper_mask = 1 << 31
	for i in range(1, 624) :
		x = (mt[i] & upper_mask) +(mt[(i+1) % 624] ^ lower_mask)
		xA = x >> 1
		if x & 1 :
			xA ^= 0x9908B0DF
		mt[i] = mt[(i + 397) % 624] ^ xA

	y = mt[-1] 
	y ^= y >> 11
	y ^= (y << 7) & 0x9d2c5680
	y ^= (y << 15) & 0xefc60000
	y ^= y >> 18
	
	return y