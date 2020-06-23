#!/bin/bash

xxd -i code.cc > source.h
gcc -lkeystone -lstdc++ -lm -lunicorn -o code emu.c