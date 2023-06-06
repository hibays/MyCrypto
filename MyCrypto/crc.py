# Cyclic Redundancy Check (CRC)

from base import Hash
from struct import pack, unpack

class CRC(Hash) :
	__slots__ = ('crc', 'crcfunc', 'width')
	
	def __new__(cls, poly=0xa001, init=None, refin=False, refout=False, xorout=None) :
		self = super().__new__(cls)
		
		width = poly.bit_length()
		self.width = width
		self.crc = (1 << width) - 1 if init is None else init
		
		def ref(num) :
			res = 0
			while num :
				res <<= 1
				if num & 1 : res |= 1
				num >>= 1
			return res
				
		def crcfunc(data, crc=self.crc, poly=poly) :
			for i in data :
				crc ^= i
				for j in range(8) :
					crc = crc >> 1 ^ poly if crc & 1 else crc >> 1
			return crc
			
		self.crcfunc = crcfunc
		
		return self
		
	def update(self, data) :
		self.crc = self.crcfunc(data, self.crc)
		
	def digest(self) :
		return self.crc.to_byte(self.width>>3, 'big')
		
	def hexdigest(self) :
		return '%0{}x'.format(self.width) % self.crc
	
	def __int__(self) :
		return self.crc
	
	def __bytes__(self) :
		raise RuntimeError('Use self.digest()!')
		
CRC4_ITU = CRC(poly=0b1011, init=0, refin=True, refout=True, xorout=None)
CRC5_EPC = CRC(poly=0b1011, init=0, refin=False, refout=False, xorout=None)

