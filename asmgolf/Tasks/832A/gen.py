import json
fd = open("cf.json","r")
d = json.loads(fd.read())
fd.close()
tests = {}
for (k,v) in d.items():
	if 'input' in k:
		num = k[len('input#')::]
		if not num in tests:
			tests[num] = {}
		s = v.split()
		tests[num]['input'] = {'RDI': int(s[0]), 'RSI':int(s[1])}
	if 'output' in k:
		num = k[len('output#')::]
		if not num in tests:
			tests[num] = {}
		if 'YES' in v:
			tests[num]['output'] = {'RAX': 1}
		else:
			tests[num]['output'] = {'RAX': 0}

for (k,v) in tests.items():
	with open("tests/"+k+'.in','w') as fi, open("tests/"+k+'.out','w') as fo:
		for (r,rv) in v['input'].items():
			print(F'{r} = {hex(rv)}',file=fi)
		for (r,rv) in v['output'].items():
			print(F'{r} = {hex(rv)}',file=fo)