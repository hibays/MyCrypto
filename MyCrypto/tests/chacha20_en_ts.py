from .tsm import *
from ..chacha20 import ChaCha20

def main() :
	data, key, nonce = bytes(2048), bytes(32), bytes(12)
	test('ChaCha20', ChaCha20(key, nonce), data, key)
