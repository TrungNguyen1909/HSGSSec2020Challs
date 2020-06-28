from random import getrandbits

for i in range(10):
	with open("tests/"+str(i)+".in","w") as fi, open("tests/"+str(i)+".out","w") as fo:
		a = getrandbits(31);
		b = getrandbits(31);
		print(F"RDI = {hex(a)}",file=fi)
		print(F"RSI = {hex(b)}",file=fi)
		print(F"RAX = {hex(a+b)}",file=fo)
		
		