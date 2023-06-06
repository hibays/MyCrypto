# The RSA Asymmetric Cipher
# Reference :
#	1.https://www.ruanyifeng.com/blog/2013/06/rsa_algorithm_part_one.html
#	2.https://www.ruanyifeng.com/blog/2013/07/rsa_algorithm_part_two.html

from .base import Asymmetric

from math import ceil, floor, gcd
from random import random
from warnings import warn

def randrange(a, b, floor=floor, random=random) :
	# return [a, b) -> int, which a < b
	return floor(b * random() + a)

# Miller Rabin Algorithm
# From https://zhuanlan.zhihu.com/p/220203643
# See https://zhuanlan.zhihu.com/p/521260342
def is_prime(n, A=(2, 325, 9375, 28178, 450775, 9780504, 1795265022)) :
	if n < 3 : # for 1, 2
		return n == 2
	if not (n & 1) : # for even
		return False

	t, h = n - 1, 0
	while not (t & 1) :
		h += 1
		t >>= 1
	for a in A :
		a %= n
		if a <= 1 : continue
		v = pow(a, t, n)
		# 检验成功 v = -1, 1
		if v == 1 or v == n - 1 :
			continue

		for i in range(1, h+1) :
			v = v * v % n
			if v == n - 1 and i != h :
				v = 1
				break
			# a^(t2^j) != \pm 1 但是a^(t2^(j+1)) = 1，说明n不是素数
			if v == 1 :
				return False
		
		if v != 1 : # a^(n - 1) % n != 1
			return False
	return True

def general_prime(bit_size=512, randfunc=randrange) :
	n, size = (1<<bit_size-2)+1, (1<<bit_size-1)-1
	while True :
		num = randfunc(n, size)
		if not(num & 1) : num = num - 1
		
		if is_prime(num) :
			return num
			
def general_pq(bit_size=512, randfunc=randrange) :
	n, size = (1<<bit_size-2)+1, (1<<bit_size-1)-1
	while True :
		prime = randfunc(n, size)
		if not(prime & 1) : prime = prime - 1
		
		if is_prime(prime) :
			break
	
	while True :
		num = randfunc(n, size)
		if not(num & 1) : num = num - 1
		
		if prime != num and is_prime(num) :
			return num, prime

# 扩展欧几里得求逆元
# See https://zhuanlan.zhihu.com/p/58241990
def exgcd(a, b) :
	# No need in Python
	#if a < b :
	#	res = exgcd(b, a)
	#	return res[1], res[0], res[-1]
	x = n = 1
	y = m = 0
	while b :
		d = a // b
		m, n, x, y, a, b = (
			x - m*d, y - n*d,
			      m,       n,
			      b,   a % b)
	return x, y, a
	

class RSA(Asymmetric) :
	
	def __new__(cls, *, p=None, q=None, bit_size=None) :
		self = super().__new__(cls)
		if bit_size is not None :
			p, q = general_pq(bit_size)
		
		# r = φ(self.N) = φ(p)φ(q) = (p-1)(q-1)
		self.N, r = p*q, (p - 1)*(q - 1) 
		del p, q
		if self.N <= 35 :
			raise ValueError('p, q too small')
		
		bs = r.bit_length()
		bs = 17 if bs > 17 else bs-1
		while True :
			# e = randrange(2, r)
			# if gcd(e, r) != 1 : continue
			e = general_prime(bs)
			if not(r % e) : continue
			
			# e and r are relatively prime
			self.public =  e
			
			x, y, a = exgcd(e, r)
			self.private = (x + r) % r if x < 0 else x
			if e != self.private :
				del r
				break
	
		return self
	
	def encrypt(self, data, public=None, N=None) :
		if public is None :
			public = self.public
		if N is None :
			N = self.N
		
		data = int.from_bytes(data, 'big')
		if data >= N :
			raise RuntimeError('data too large(>= %s) to be crypt! Try RSA_BLOCK.' % N)
		data = pow(data, public, N)
		data = data.to_bytes(ceil(data.bit_length()/8), 'big')
		return data
		
	def decrypt(self, data, private=None, N=None) :
		if private is None :
			private = self.private
		return self.encrypt(data, private, N)


class RSA_BLOCK(RSA) :
	
	def __new__(*args, **kwds) :
		self = super().__new__(*args, **kwds)
		self._init(self.N)
		return self
		
	def _init(self, N) :
		# note: N at least largrer than 127
		t = N.bit_length() / 8
		# each block_size data generate gblock_size data in encrypt
		# so is the reduction
		self.gblock_size, self.block_size = \
			ceil(t), floor(t)
		
	@classmethod
	def from_rsa(cls, rsa) :
		self = object.__new__(cls)
		self.private, self.public, self.N = \
			rsa.private, rsa.public, rsa.N
		self._init(self.N)
		return self
			
	def itercrypt(self, data, key=None, N=None, *, encrypt) :
		if N is None :
			N = self.N
		else :
			self._init(N)
		if encrypt :
			if key is None :
				key = self.public
			gblock_size, block_size = \
				self.gblock_size, self.block_size
		else :
			if key is None :
				key = self.private
			gblock_size, block_size = \
				self.block_size, self.gblock_size
				
		dl = len(data)
		
		if dl % block_size :
			warn('{} Algorithm data length better be multiples of {}'
				.format(self.__class__.__name__, block_size))
		
		blocks = map(
			data.__getitem__,
			map(
				lambda i,s=slice,bs=block_size: s(i, i + bs, None),
				range(0, dl, block_size)
			)
		)
		
		for block in blocks :
			block = int.from_bytes(block, 'little')
			block = pow(block, key, N)
			yield block.to_bytes(gblock_size, 'little')
	
	def encrypt(self, data, public=None, N=None) :
		return b''.join(self.itercrypt(data, public, N, encrypt=True))
		
	def decrypt(self, data, private=None, N=None) :
		return b''.join(self.itercrypt(data, private, N, encrypt=False))
		