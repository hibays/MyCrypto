# Pseudo-random Number Generator

# Xorshift RNGs
# See https://gist.github.com/AbsoluteVirtue/82a1913196fe0922262930ee81c327cb
def Xorshift32(n) :
	# Algorithm "xor" from p. 4 of Marsaglia, "Xorshift RNGs"
	n ^= n << 13; n ^= n >> 17; n ^= n << 5
	return n

def Xorshift64s(n) :
	# Xorshift64s, variant A_1(12,25,27) with multiplier M_32 from line 3 of table 5
	n ^= n << 12; n ^= n >> 25; n ^= n << 27
	return n * 0x2545f4914f6cdd1d
	
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
