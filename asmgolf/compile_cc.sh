#!/bin/bash

xxd -i code.cc > source.h
cc -o code emu.c -lkeystone -lstdc++ -lm -lpthread -lunicorn
