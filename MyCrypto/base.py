# The base class of all cryptography classes.
# It's some methods that cryptography classes
# 	are used together.
# Also some attributes.

__all__ = [
	'Cipher',
		'Asymmetric',
		'Symmetric',
			'BlockCipher',
			'StreamCipher',
	'Hash',
	'Random',
		'PRNG',
]

_OFB, _CFB, _CBC, _CTR, _ECB = (
	'OFB', 'CFB', 'CBC', 'CTR', 'ECB')


class Cipher(object) :
	__slots__ = ()
	
	def __new__(cls) :
		self = super().__new__(cls)
		return self


class Asymmetric(Cipher) :
	__slots__ = ()
	

class Symmetric(Cipher) :
	__slots__ = ()
	

class BlockCipher(Symmetric) :
	__slots__ = ('mode', 'iv')
	
	def __new__(cls, mode, iv=None) :
		self = super().__new__(cls)
		
		self.mode = mode
		if mode == _ECB :
			pass
			
		elif mode == _CBC :
			if iv is None :
				iv = bytes(cls.block_size)
				
			elif len(iv) != 8 :
				raise ValueError('for {} Algorithm, IV must be length {} bytes'
					.format(cls.__name__, cls.block_size))
					
			self.iv = iv
		
		else :
			raise NotImplementedError('Mode {} has not implemented'
				.format(mode))
				
		return self
		
	def itercrypt(self, data, block_generator) :
		bs, dl = self.__class__.block_size, len(data)
		if dl & bs-1 : # Little track
			raise ValueError('{} Algorithm data length must be multiples of {}'
				.format(self.__class__.__name__, bs))
		
		blocks = map(
			data.__getitem__,
			map(
				lambda i,s=slice,bs=bs: s(i, i + bs, None),
				range(0, dl, bs)
			)
		)
		
		if self.mode == _ECB :
			return map(block_generator, blocks)
			
		elif self.mode == _CBC :
			def temp(
				# note: it use function name to sign
				sign='encrypt' in block_generator.__name__,
				bxor=lambda a,b,bytes=bytes: bytes(i ^ j for i,j in zip(a, b)),
				block_generator=block_generator,
			) :
				if sign :
					_last_cipherblock = block_generator(bxor(next(blocks), self.iv))
					yield _last_cipherblock
					for block in blocks :
						_last_cipherblock = block_generator(bxor(block, _last_cipherblock))
						yield _last_cipherblock
				else :
					_last_cipherblock = next(blocks)
					yield bxor(block_generator(_last_cipherblock), self.iv)
					for block in blocks :
						yield bxor(block_generator(block), _last_cipherblock)
						_last_cipherblock = block
				
			return temp()
			
		elif self.mode == _CTR :
			...
			
		elif self.mode == _CFB :
			...
			
		elif self.mode == _OFB :
			...

		else :
			raise ValueError('Unsupported mode: {}'.format(self.mode))
		
	def encrypt(self, data) :
		return b''.join(self.itercrypt(data, self.encrypt_block))
	
	def decrypt(self, data) :
		return b''.join(self.itercrypt(data, self.decrypt_block))
		
	MODE_OFB, MODE_CFB, MODE_CBC, MODE_CTR, MODE_ECB = (
		_OFB, _CFB, _CBC, _CTR, _ECB)


class StreamCipher(Symmetric) :
	__slots__ = ('keystream',)
	
	# Most common stream cipher use xor
	# So the decrypt is total the same of encrypt
	def itercrypt(self, data, _xor=lambda a,b: a^b) :
		return map(_xor, self.keystream(), data)
	
	def crypt(self, data) :
		return bytes(self.itercrypt(data))
	
	encrypt = decrypt = crypt


class Hash(object) :
	__slots__ = ()


class Random(object) :
	__slots__ = ()


class PRNG(Random) :
	__slots__ = ()
	