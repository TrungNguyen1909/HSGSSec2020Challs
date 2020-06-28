start:
	mov rax, rdi
	idiv rsi
	shl rax, 63
	shr rax, 63
	hlt