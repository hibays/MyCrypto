from .tsm import *
from ..aes import AES

def formataeskey(b: bytes) :
	l = len(b)
	if l > 32 :
		from hashlib import blake2s
		return blake2s(b).digest()
	if not (l & 7) :
		return b
	if l > 24 :
		return b + bytes(32-(l & 31))
	if l > 16 :
		return b + bytes(24-(l & 23))
	return b + bytes(16-(l & 15))
	
try :
	from pyaes import AES as _AES
	_AES.MODE_ECB = AES.MODE_ECB
except :
	...
	
def main() :
	#AES = _AES
	data = urandom(128)
	key = b'0123456789101112'
	MODE = AES.MODE_ECB
	
	test('AES128 ECB TEST', AES(key, MODE), data, key)
	
	key += b'13141516'
	test('AES192 ECB TEST', AES(key, MODE), data, key)
	
	key += b'17181920'
	test('AES256 ECB TEST', AES(key, MODE), data, key)
	