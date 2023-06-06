# The ChaCha20 Algorithm
# See  https://datatracker.ietf.org/doc/html/rfc8439 (ietf)
# Also https://datatracker.ietf.org/doc/html/rfc7539
# See  https://tools.ietf.org/html/draft-arciszewski-xchacha-03 (XChaCha20)
# Also https://cr.yp.to/chacha/chacha-20080120.pdf
# Note: the implementation does not support 16-byte key

from os import urandom
from array import array
from struct import unpack, pack
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
	# Odd round
	x[0], x[4], x[ 8], x[12] = QUARTERROUND(x[0], x[4], x[ 8], x[12]); # column 0
	x[1], x[5], x[ 9], x[13] = QUARTERROUND(x[1], x[5], x[ 9], x[13]); # column 1
	x[2], x[6], x[10], x[14] = QUARTERROUND(x[2], x[6], x[10], x[14]); # column 2
	x[3], x[7], x[11], x[15] = QUARTERROUND(x[3], x[7], x[11], x[15]); # column 3
	
	# Even round
	x[0], x[5], x[10], x[15] = QUARTERROUND(x[0], x[5], x[10], x[15]); # diagonal 1 (main diagonal)
	x[1], x[6], x[11], x[12] = QUARTERROUND(x[1], x[6], x[11], x[12]); # diagonal 2
	x[2], x[7], x[ 8], x[13] = QUARTERROUND(x[2], x[7], x[ 8], x[13]); # diagonal 3
	x[3], x[4], x[ 9], x[14] = QUARTERROUND(x[3], x[4], x[ 9], x[14]); # diagonal 4


class ChaCha20(StreamCipher) :
	__slots__ = ('keystream', '_nonce', '__key', '__basemat')
	
	def __new__(cls, key, nonce=None) :
		#   key: 32 byte (256 bit)
		# nonce:  8 byte ( 64 bit) (original ChaCha20)
		# count:  8 byte ( 64 bit) (original ChaCha20)
		# nonce: 12 byte ( 96 bit) (RFC: 8439) (Default)
		# count:  4 byte ( 32 bit) (RFC: 8439)
		# nonce: 24 byte (128 bit) (XChaCha20) (still in draft stage)
		self = super().__new__(cls)
		if nonce is None : nonce = urandom(12)
		
		self.__key = unpack('<IIIIIIII', key)
		self.nonce = nonce # unpack('<III', nonce)
		
		return self
	
	@property
	def nonce(self) :
		return self._nonce
		
	@nonce.setter
	def nonce(self, b8_12_24: bytes) :
		# the little nonce design makes a difficult
		if len(b8_12_24) == 8 :
			n8_12_24 = unpack('<II', b8_12_24)
			def stream(keys=self.__key, nonces=n8_12_24) :
				mat = array('I', (
					0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
					*keys, # own 8 index
					0, 0, *nonces))
				counter = 0
				while True :
					x = mat[:]
					for _ in range(10) : XROUND2(x)
					for i,j in enumerate(mat) :
						x[i] = x[i] + j & 0xffffffff
					for i in x.tobytes() :
						yield i
					counter += 1
					if counter & ~0xffffffff : # as > ..32bit
						mat[12], mat[13] = counter&0xffffffff, counter>>32
					else :
						mat[13] = counter
					
		elif len(b8_12_24) == 12 :
			n8_12_24 = unpack('<III', b8_12_24)
			def stream(keys=self.__key, nonces=n8_12_24) :
				mat = array('I', (
					0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
					*keys,
					0, *nonces))
				while True :
					x = mat[:]
					for _ in range(10) : XROUND2(x)
					for i,j in enumerate(mat) :
						x[i] = x[i] + j & 0xffffffff
					for i in x.tobytes() :
						yield i
					mat[8] += 1 # ++counter
					
		elif len(b8_12_24) == 24 :
			def HChaCha20(b16_m4) :
				mat = array('I', (
					0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
					*self.__key,
					*b16_m4))
				x = mat[:]
				for _ in range(10) : XROUND2(x)
				# take the only first 128 bits & last 128 bits
				return x[:4] + x[12:]
			
			self.__key = HChaCha20(unpack('<IIII', b8_12_24[:16]))
			self.nonce = b'\0\0\0\0' + b8_12_24[16:] # note: recursive
			return
			
		else :
			raise ValueError('Chacha20 nonce must be either 16, 24, or 32 bytes long, not {}.'
					.format(len(b8_12_24)))
		self.keystream = stream
