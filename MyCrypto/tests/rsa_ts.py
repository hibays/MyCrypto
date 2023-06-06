from .tsm import *
from ..rsa import *

def main(pf=p) :
	test('RSA')
	p, q = general_pq(128)
	
	print('p = %s'%p, 'q = %s'%q, sep='\n')
	Cipher = RSA(p=p, q=q)
	print('N =', Cipher.N)
	print('euler(N) =', (p-1)*(q-1))
	print(' public =', Cipher.public)
	if Cipher.private.bit_length() < 256 :
		print('private =', Cipher.private)
	else :
		print('private bits', Cipher.private.bit_length())

	data = b'\x08'
	
	print()
	encryptdata = Cipher.encrypt(data)
	print('encryptdata', encryptdata)
	
	decryptdata = Cipher.decrypt(encryptdata)
	print('decryptdata', decryptdata)
	
	print()
	print(pf(data == decryptdata))
	
	test('RSA BLOCK')
	
	Cipher = RSA_BLOCK.from_rsa(Cipher)
	print('block_size =', Cipher.block_size)
	print('gblock_size =', Cipher.gblock_size)
	
	data = b'i was a human.but now I am not sure that is true or not.'
	
	print()
	encryptdata = Cipher.encrypt(data)
	print('encryptdata', encryptdata)
	
	decryptdata = Cipher.decrypt(encryptdata)
	print('decryptdata', decryptdata)
	
	print()
	print(pf(data == decryptdata))
	