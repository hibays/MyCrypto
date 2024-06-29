# 
from os import urandom
from base64 import (
	b64encode as e64,
	b85encode as e85,
)
try :
	from fmat.test import gt, gprint as print
except :
	...
p = lambda s : 'Succeed!\n' if s else 'Failed!\n'
e16 = b'%x'.__mod__

def pad(b, mup=16) :
	tag = len(b) % mup
	return b''.join((b, (myp-tag)*bytes((mul-tag,)))) if tag else b
def unpad(b, mup=16) :
	return b if (len(b) % mup) else b[:-b[-1]]

def test(title, cipher=None, data=None, key=None, prf=e85) :
	if type(prf) is dict :
		_ = {
			'': ...
		}
	if type(key) not in (list, tuple) :
		key = (key,)
	
	print('<', title.join('\t\t').center(52, '-'), '>\n')
	if data is not None :
		print('  Plaintext:', prf(data))
	if key[0] is not None :
		print('        Key:', *map(prf, key))
	
	if data is not None :
		print()
		crypttext = (cipher.encrypt)(data)
		print('Encrypttext:', prf(crypttext))
		
		decrypttext = (cipher.decrypt)(crypttext)
		if decrypttext != data :
			print('Decrypttext:', prf(decrypttext))
	
		print()
		print(decrypttext==data, func=p)
	