from .tsm import *
from ..sm4 import SM4

def main() :
	data = urandom(3200)
	key = b'0123456789101112'#urandom(16)
	
	test('SM4 ECB TEST',
		SM4(key),
		data, key)