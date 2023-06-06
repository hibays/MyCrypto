# The ChaCha20 Algorithm
# See  https://datatracker.ietf.org/doc/html/rfc8439
# Also https://datatracker.ietf.org/doc/html/rfc7539
# Also https://datatracker.ietf.org/doc/html/rfc7905
# Also https://cr.yp.to/chacha/chacha-20080128.pdf

from os import urandom
from array import array
from struct import unpack
from .base import StreamCipher

def ROT32L(i32, n) :
	return i32 << n & 0xffffffff | i32 >> 32-n

def QUARTERROUND(a, b, c, d, ROT32L=ROT32L) : # a,b,c,d: int32
	a = a+b & 0xffffffff; d = ROT32L(d ^ a,16);
	c = c+d & 0xffffffff; b = ROT32L(b ^ c,12);
	a = a+b & 0xffffffff; d = ROT32L(d ^ a, 8);
	c = c+d & 0xffffffff; b = ROT32L(b ^ c, 7);
	return a, b, c, d

def XROUND2(x, QUARTERROUND=QUARTERROUND) :
	# Row exchange
	(x[ 0], x[ 1], x[ 2], x[ 3],
	 x[ 4], x[ 5], x[ 6], x[ 7],
	 x[ 8], x[ 9], x[10], x[11],
	 x[12], x[13], x[14], x[15]) = (
		x[0], x[4], x[ 8], x[12],
		x[1], x[5], x[ 9], x[13],
		x[2], x[6], x[10], x[14],
		x[3], x[7], x[11], x[15])
	# Odd round
	x[0], x[4], x[ 8], x[12] = QUARTERROUND(x[0], x[4], x[ 8], x[12]); # column 0
	x[1], x[5], x[ 9], x[13] = QUARTERROUND(x[1], x[5], x[ 9], x[13]); # column 1
	x[2], x[6], x[10], x[14] = QUARTERROUND(x[2], x[6], x[10], x[14]); # column 2
	x[3], x[7], x[11], x[15] = QUARTERROUND(x[3], x[7], x[11], x[15]); # column 3
	# Column exchange
	(x[ 0], x[ 1], x[ 2], x[ 3],
	 x[ 4], x[ 5], x[ 6], x[ 7],
	 x[ 8], x[ 9], x[10], x[11],
	 x[12], x[13], x[14], x[15]) = (
		x[0], x[5], x[10], x[15],
		x[1], x[6], x[11], x[12],
		x[2], x[7], x[ 8], x[13],
		x[3], x[4], x[ 9], x[14])
	# Even round
	x[0], x[5], x[10], x[15] = QUARTERROUND(x[0], x[5], x[10], x[15]); # diagonal 1 (main diagonal)
	x[1], x[6], x[11], x[12] = QUARTERROUND(x[1], x[6], x[11], x[12]); # diagonal 2
	x[2], x[7], x[ 8], x[13] = QUARTERROUND(x[2], x[7], x[ 8], x[13]); # diagonal 3
	x[3], x[4], x[ 9], x[14] = QUARTERROUND(x[3], x[4], x[ 9], x[14]); # diagonal 4


class ChaCha20(StreamCipher) :
	__slots__ = ('keystream', '_nonce')
	
	def __new__(cls, key, nonce=None) :
		#   RFC: 8439
		#   key: 32 byte (256 bit)
		# nonce: 12 byte ( 96 bit)
		# count:  4 byte ( 32 bit)
		self = super().__new__(cls)
		if nonce is None : nonce = urandom(12)
		
		def stream(keys=unpack('<IIIIIIII', key), nonces=unpack('<III', nonce)) :
			mat = array('I', (
				0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
				*keys,
				0, *nonces))
			while True :
				x = mat[:]
				for _ in range(10) : XROUND2(x)
				for i,j in enumerate(mat) :
					x[i] = x[i] + j & 0xffffffff
				for i in x.tobytes()[::-1] :
					yield i
				mat[8] += 1 # ++count
			
		self.keystream, self._nonce = \
			stream, nonce
		
		return self
	
	#nonce = property(lambda s: s._nonce)
	@property
	def nonce(self) :
		return self._nonce
		
	@nonce.setter
	def nonce(self, b12) :
		self.keystream, self._nonce = (
			(lambda f=self.keystream,s=unpack('<III', b12): f(nonces=s)),
			b12
		)
