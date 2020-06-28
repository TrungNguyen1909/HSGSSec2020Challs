mov rcx, rdi
sub rcx, 2
xor rdi, rdi
inc rdi
xor rsi, rsi
inc rsi
l:
lea rax, [rdi + rsi]
mov rdi, rsi
mov rsi, rax
loop l
mov rax, rsi
hlt