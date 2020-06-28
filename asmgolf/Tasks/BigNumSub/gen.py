from random import getrandbits

for i in range(60):
	with open("tests/"+str(i)+".in","w") as fi, open("tests/"+str(i)+".out","w") as fo:
		a = getrandbits(128)
		b = getrandbits(128)
		c = (a-b)&0xffffffffffffffffffffffffffffffff
		assert(c>=0)
		print(F"RDI = {hex(a&0xffffffffffffffff)}",file=fi)
		print(F"RSI = {hex(a>>64)}",file=fi)
		print(F"RDX = {hex(b&0xffffffffffffffff)}",file=fi)
		print(F"RCX = {hex(b>>64)}",file=fi)
		print(F"RAX = {hex(c&0xffffffffffffffff)}",file=fo)
		print(F"RDX = {hex(c>>64)}",file=fo)
