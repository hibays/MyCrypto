# the Rivest Cipher 4 (RC4)
# See  https://cypherpunks.venona.com/archive/1994/09/msg00304.html
# Also http://www.users.zetnet.co.uk/hopwood/crypto/scan/cs.html#RC4
# Also https://datatracker.ietf.org/doc/html/draft-kaukonen-cipher-arcfour-03
#
# RC4 Pseudo-Random Generation Algorithm (PRGA) (RC4⁺)
# See http://eprint.iacr.org/2008/396.pdf

from .base import StreamCipher

class RC4(StreamCipher) :
	__slots__ = ('keystream',)
	
	def __new__(cls, key, *, sbox_size=1<<8) :
		self = super().__new__(cls)
		if sbox_size & sbox_size-1 :
			print('sbox_size better be 2^n, otherwise might cause bugs')
		
		_lkey, _bs, j = len(key), sbox_size - 1, 0
		
		# KSA: A key-scheduling algorithm
		S = bytearray(range(sbox_size))
		for i in range(sbox_size) :
			j = j + S[i] + key[i % _lkey] & _bs
			S[i], S[j] = S[j], S[i]
		
		# PRGA: Pseudo random generation algorithm
		def stream(i=0, j=0, _bs=_bs, S=S) :
			S = S[::] # copy S
			while True:
				i =    1+i & _bs
				j = S[i]+j & _bs
				S[i], S[j] = S[j], S[i]
			
				yield S[S[i]+S[j] & _bs]
				
		self.keystream = stream
		
		return self
	

class RC4P(RC4) :
	__slots__ = ('keystream',)
	
	def __new__(cls, key, *, sbox_size=1<<8) :
		self = object.__new__(cls)
		if sbox_size & sbox_size-1 :
			print('sbox_size better be 2^n, otherwise might cause bugs')
		
		_lkey, _bs, j = len(key), sbox_size-1, 0
		if not _lkey or _lkey > sbox_size :
			raise ValueError('secret key length must in [1, {}], but {} entered'
				.format(sbox_size, _lkey))
			
		# KSA^+: A key-scheduling algorithm
		S = bytearray(range(sbox_size))
		
		# Layer 1: Basic Scrambling
		for i in range(sbox_size) :
			j = j + S[i] + key[i % _lkey] & _bs
			S[i], S[j] = S[j], S[i]
		
		_hbs = sbox_size >> 1
		# >>> Definition of IV
		# ❌this part i don't very understand
		iv = tuple(range(_lkey))
		def IV(y) :
			if _hbs-_lkey <= y <= _hbs-1 :
				return iv[_hbs-1-y]
			elif _hbs <= y <= _hbs+_lkey-1 :
				return iv[y-_hbs]
			return 0
		IV = list(map(IV, range(sbox_size)))
		
		# Layer 2: Scrambling with IV
		for i in range(_hbs-1, 0, -1) :
			j = (j+S[i] ^ key[i % _lkey]+IV[i]) & _bs
			S[i], S[j] = S[j], S[i]
		
		for i in range(_hbs, sbox_size, 1) :
			j = (j+S[i] ^ key[i % _lkey]+IV[i]) & _bs
			S[i], S[j] = S[j], S[i]
			
		# Layer 3: Zigzag Scrambling
		for y in range(sbox_size) :
			i = (sbox_size - (y-1 >> 1) if y & 1  else y >> 1) & _bs
			j = j+S[i]+key[i % _lkey] & _bs
			S[i], S[j] = S[j], S[i]
		
		# PRGA^+: Pseudo random generation algorithm
		def stream(i=0, j=0, _bs=_bs, S=S) :
			S = S[::] # copy S-box
			while True:
				i =    1+i & _bs
				j = S[i]+j & _bs
				S[i], S[j] = S[j], S[i]
				
				t, ta, tb = (
					S[i]+S[j] & _bs,
					S[(i >> 3 ^ j << 5) & _bs]+S[(j >> 3 ^ i << 5) & _bs] ^ 0xAA,
					j+S[j] & _bs,
				)
				
				yield S[t]+S[ta & _bs] & _bs ^ S[tb]
				
		self.keystream = stream
		
		return self
	