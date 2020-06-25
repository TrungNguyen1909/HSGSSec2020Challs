all: debugger

debugger: debugger.c emu.h
	g++ -o debugger debugger.c -lkeystone -lstdc++ -lm -lunicorn -lcapstone
