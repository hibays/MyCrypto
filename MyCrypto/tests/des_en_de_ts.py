from .tsm import *
from ..des import DES, TripleDES

def main() :
	data = urandom(128)
	key = urandom(8)
	
	test('DES ECB TEST',
		DES(key),
		data, key)
	
	data = urandom(128)
	key = urandom(8)
	iv = urandom(8)
	
	test('DES CBC TEST',
		DES(key, DES.MODE_CBC, iv),
		data, key)
	
	data = urandom(128)
	key = (urandom(8), urandom(8), urandom(8))
	
	test('3DES ECB TEST',
		TripleDES(*key),
		data, key)
		
	iv = urandom(8)
	
	test('3DES CBC TEST',
		TripleDES(*key, TripleDES.MODE_CBC, iv),
		data, key)
		
		