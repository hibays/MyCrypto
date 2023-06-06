from .tsm import *
from ..zuc import ZUC

def main() :
	data, key = urandom(127), urandom(16)
	test('ZUC', ZUC(key), data, key)