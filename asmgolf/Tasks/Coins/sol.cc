cmp rdi, rsi
jl .b1
inc rax
hlt
.b1:
mov rax, rsi
idiv rdi
test rdx, rdx
jz .b2
inc rax
.b2:
hlt
