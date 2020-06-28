#!/bin/bash

xxd -i code.cc > source.h
cc -Ofast -o code emu.c -lkeystone -lstdc++ -lm -lpthread -lunicorn
