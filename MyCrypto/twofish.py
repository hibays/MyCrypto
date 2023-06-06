# The TwoFish Algorithm
# See http://www.counterpane.com/twofish.html

class TwoFish(object) :
	def __new__(cls, key) :
		self = super().__new__(cls)
		...