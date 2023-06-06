# THE DATA ENCRYPTION STANDARD (DES)
# THE TRIPLE DES (3DES)
# See http://csrc.nist.gov/publications/fips/fips46-3/fips46-3.pdf

from .base import BlockCipher
from array import array
from struct import unpack, pack

INITIAL_PERMUTATION = bytes((
	57, 49, 41, 33, 25, 17,  9, 1,
	59, 51, 43, 35, 27, 19, 11, 3,
	61, 53, 45, 37, 29, 21, 13, 5,
	63, 55, 47, 39, 31, 23, 15, 7,
	56, 48, 40, 32, 24, 16,  8, 0,
	58, 50, 42, 34, 26, 18, 10, 2,
	60, 52, 44, 36, 28, 20, 12, 4,
	62, 54, 46, 38, 30, 22, 14, 6,
))

INVERSE_PERMUTATION = bytes((
	39, 7, 47, 15, 55, 23, 63, 31,
	38, 6, 46, 14, 54, 22, 62, 30,
	37, 5, 45, 13, 53, 21, 61, 29,
	36, 4, 44, 12, 52, 20, 60, 28,
	35, 3, 43, 11, 51, 19, 59, 27,
	34, 2, 42, 10, 50, 18, 58, 26,
	33, 1, 41,  9, 49, 17, 57, 25,
	32, 0, 40,  8, 48, 16, 56, 24,
))

EXPANSION = bytes((
	31,  0,  1,  2,  3,  4,
	 3,  4,  5,  6,  7,  8,
	 7,  8,  9, 10, 11, 12,
	11, 12, 13, 14, 15, 16,
	15, 16, 17, 18, 19, 20,
	19, 20, 21, 22, 23, 24,
	23, 24, 25, 26, 27, 28,
	27, 28, 29, 30, 31,  0,
))

PERMUTATION = bytes((
	15,  6, 19, 20, 28, 11, 27, 16,
	 0, 14, 22, 25,  4, 17, 30,  9,
	 1,  7, 23, 13, 31, 26,  2,  8,
	18, 12, 29,  5, 21, 10,  3, 24,
))

PERMUTED_CHOICE1 = bytes((
	56, 48, 40, 32, 24, 16,  8,
	 0, 57, 49, 41, 33, 25, 17,
	 9,  1, 58, 50, 42, 34, 26,
	18, 10,  2, 59, 51, 43, 35,
	62, 54, 46, 38, 30, 22, 14,
	 6, 61, 53, 45, 37, 29, 21,
	13,  5, 60, 52, 44, 36, 28,
	20, 12,  4, 27, 19, 11,  3,
))

PERMUTED_CHOICE2 = bytes((
	13, 16, 10, 23,  0,  4,
	 2, 27, 14,  5, 20,  9,
	22, 18, 11,  3, 25,  7,
	15,  6, 26, 19, 12,  1,
	40, 51, 30, 36, 46, 54,
	29, 39, 50, 44, 32, 47,
	43, 48, 38, 55, 33, 52,
	45, 41, 49, 35, 28, 31,
))


SUBSTITUTION_BOX1 = bytes((
	14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7,
	 0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8,
	 4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0,
	15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13,
))
SUBSTITUTION_BOX2 = bytes((
	15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10,
	 3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5,
	 0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15,
	13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9,
))
SUBSTITUTION_BOX3 = bytes((
	10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8,
	13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1,
	13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7,
	 1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12,
))
SUBSTITUTION_BOX4 = bytes((
	 7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15,
	13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9,
	10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4,
	 3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14,
))
SUBSTITUTION_BOX5 = bytes((
	 2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9,
	14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6,
	 4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14,
	11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3,
))
SUBSTITUTION_BOX6 = bytes((
	12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11,
	10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8,
	 9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6,
	 4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13,
))
SUBSTITUTION_BOX7 = bytes((
	 4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1,
	13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6,
	 1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2,
	 6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12,
))
SUBSTITUTION_BOX8 = bytes((
	13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7,
	 1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2,
	 7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8,
	 2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11,
))

ROTATES = bytes((1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1,))


class DES(BlockCipher) :
	__slots__ = ('K', 'iK') + BlockCipher.__slots__
	
	def __new__(cls, key, mode=BlockCipher.MODE_ECB, iv=bytes(8)) :
		self = super().__new__(cls, mode, iv)
		if len(key) != 8 :
			raise ValueError('key must be a length 8 bytes.')
		
		# Initialize the K s
		self.K = array('Q')
		
		# Computing key exchange
		k56, k64 = 0, unpack('>Q', key)[0]
		for i,j in enumerate(PERMUTED_CHOICE1) :
			k56 |= (k64 >> 63-j & 1) << 55-i
		
		# get C0, D0
		C, D = k56 >> 28, k56 & 0xfffffff

		for i in ROTATES :
			# (C, D) <<<= i
			C = C << i & 0xfffffff | C >> 28-i
			D = D << i & 0xfffffff | D >> 28-i
			
			k48, k56 = 0, C << 28 | D
			for j,k in enumerate(PERMUTED_CHOICE2) :
				k48 |= (k56 >> 55-k & 1) << 47-j
			self.K.append(k48)
		
		self.iK = self.K[::-1]
		
		return self
		
	def f(self, i32, k48) :
		# E exchange and key xor
		for i,j in enumerate(EXPANSION) :
			# A Trick That
			# k48 ^= (i32 >> 31-j & 1) << 47-i
			k48 ^= (i32 >> j & 1) << i
		
		# S-Box exchange
		# i32 = 0
		# for i,box in enumerate(SUBSTITUTION_BOXs) :
		# 	i6 = k48 >> 42 - i*6 # It it not necessary to &0x3f
		# 	i32 = i32 << 4 | box[i6 >> 1 & 15 | (i6 & 1) << 4 | i6 & 32]
		i32 = (
			(SUBSTITUTION_BOX8[k48 >>  1 & 15 | k48 <<  4 & 16 | k48       & 32] |
			(SUBSTITUTION_BOX7[k48 >>  7 & 15 | k48 >>  2 & 16 | k48 >>  6 & 32] |
			(SUBSTITUTION_BOX6[k48 >> 13 & 15 | k48 >>  8 & 16 | k48 >> 12 & 32] |
			(SUBSTITUTION_BOX5[k48 >> 19 & 15 | k48 >> 14 & 16 | k48 >> 18 & 32] |
			(SUBSTITUTION_BOX4[k48 >> 25 & 15 | k48 >> 20 & 16 | k48 >> 24 & 32] |
			(SUBSTITUTION_BOX3[k48 >> 31 & 15 | k48 >> 26 & 16 | k48 >> 30 & 32] |
			(SUBSTITUTION_BOX2[k48 >> 37 & 15 | k48 >> 32 & 16 | k48 >> 36 & 32] |
			 SUBSTITUTION_BOX1[k48 >> 43 & 15 | k48 >> 38 & 16 | k48 >> 42 & 32] << 4) << 4) << 4) << 4) << 4) << 4) << 4))
			
		# P exchange
		res32 = 0
		for i,j in enumerate(PERMUTATION) :
			res32 |= (i32 >> 31-j & 1) << 31-i
		
		return res32
		
	def encrypt_block(self, block, en=True) :
		b64, _b64 = 0, unpack('>Q', block)[0]
		for i,j in enumerate(INITIAL_PERMUTATION) :
			b64 |= (_b64 >> j & 1) << i
		
		b32l, b32r = b64 >> 32, b64 & 0xffffffff
		for k in (self.K if en else self.iK) :
			b32l, b32r = b32r, b32l ^ self.f(b32r, k)
		
		# IP' exchange
		b64, _b64 = 0, b32r << 32 | b32l
		for i,j in enumerate(INVERSE_PERMUTATION) :
			b64 |= (_b64 >> j & 1) << i
			
		return pack('>Q', b64)
		
	decrypt_block = lambda self, block: self.encrypt_block(block, False)
	
	block_size = 8
	
		
class TripleDES(DES) :
	__slots__ = ('encrypt_block', 'decrypt_block') + BlockCipher.__slots__
	
	# encrypt: C = Ek3(Dk2(Ek1(P)))
	# decrypt: P = Dk1(EK2(Dk3(C)))
	def __new__(cls, k1, k2, k3=None, mode=BlockCipher.MODE_ECB, iv=bytes(8)) :
		if k3 is None : k3 = k1
		self = BlockCipher.__new__(cls, mode, iv)
		
		d1, d2, d3 = DES(k1), DES(k2), DES(k3)
		
		def encrypt_block(data,
			eb1=d1.encrypt_block,
			db2=d2.decrypt_block,
			eb3=d3.encrypt_block,
		) : return eb3(db2(eb1(data)))
		
		def decrypt_block(data,
			db1=d1.decrypt_block,
			eb2=d2.encrypt_block,
			db3=d3.decrypt_block,
		) : return db1(eb2(db3(data)))
			
		self.encrypt_block, self.decrypt_block = (
			encrypt_block, decrypt_block)
			
		return self
		