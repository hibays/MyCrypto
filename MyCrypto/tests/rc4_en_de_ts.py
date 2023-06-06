from .tsm import *
from ..rc4 import RC4, RC4P

def main() :
	data, key = urandom(1000), urandom(256)
	test('RC4', RC4(key), data, key)
	test('RC4⁺ (PRGA)', RC4P(key), data, key)
	