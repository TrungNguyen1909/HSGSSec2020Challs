all: debugger

debugger: debugger.c emu.h
	gcc -o debugger debugger.c -lkeystone -lstdc++ -lm -lunicorn -lcapstone -lpthread
