all: reverse1 reverse2 reverse3 hmm1
reverse1: reverse1.s
	nasm reverse1.s -f elf64
	ld -o reverse1 reverse1.o
reverse2: reverse2.s
	nasm reverse2.s -f elf64
	ld -o reverse2 reverse2.o
reverse3: reverse3.s
	nasm reverse3.s -f elf64
	ld -o reverse3 reverse3.o
hmm1: hmm1.s
	nasm hmm1.s -f elf64
	ld -o hmm1 hmm1.o
clean:
	rm -f reverse1 reverse1.o reverse2 reverse2.o reverse3 reverse3.o hmm1 hmm1.o
