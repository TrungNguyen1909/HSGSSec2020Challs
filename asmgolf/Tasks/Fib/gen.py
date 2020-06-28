tests = [5,18,23,30,40,50,63, 73, 84, 90]
t = 0
for n in tests:
	f = [0]*(n+1)
	f[0] = f[1] = f[2] = 1
	for i in range(3, n+1):
		f[i] = f[i-1]+f[i-2]
	with open("tests/"+str(t)+".in","w") as fi, open("tests/"+str(t)+".out","w") as fo:
		assert(f[n].bit_length()<64)
		print(F"RDI = {hex(n)}",file=fi)
		print(F"RAX = {hex(f[n])}",file=fo)
	t+=1
