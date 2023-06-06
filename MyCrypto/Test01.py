from _prng import *
from random import randrange
from pprint import pprint
from _crc import *
from _numhash import *

def hittest(func, size=100003) :
	tts = {}
	avg_point = 0
	
	# 1. order number test
	order = list(func(i) % size for i in range(size, size+size*7, 7))
	order_s = size - len(set(order))
	point_1 = order_s / size
	avg_point += point_1
	tts['order'] = point_1
	
	# 2. random number test
	rand = set(randrange(i, i+size) for i in order)
	rand = list(func(i) % size for i in rand)
	rand_s = size - len(set(rand))
	point_2 = rand_s / size
	avg_point += point_2
	tts['random'] = point_2
	
	avg_point /= len(tts)
	return tts, avg_point

def s2(*nums, len=len) :
	len = len(nums)
	return sum(map(lambda n, avg=sum(nums) / len: \
		(n-avg)*(n-avg), nums)) / len

def avgtest(func, size=100003) :
	# 1. order number test
	od = {}
	for i in range(size, size*32, 31) :
		i = func(i) % size
		od[i] = od.get(i, 0) + 1
	for i in range(size) :
		od[i] = od.get(i, 0)
		
	pprint(od)
	pprint(s2(*od.values()))
	return

def main() :
	print(avgtest(Xorshift64h))
	
if __name__ == '__main__' :
	main()
