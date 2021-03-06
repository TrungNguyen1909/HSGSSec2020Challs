SYS_EXIT equ 0x3c
SYS_READ equ 0x0
SYS_WRITE equ 0x1
section .text
global _start
_start:
	push rbp
	mov rbp, rsp
	; Print welcome message
	xor rdi, rdi
	inc rdi
	lea rsi, [rel welcome_msg]
	mov rdx, end_welcome_msg
	sub rdx, rsi
	mov rax, SYS_WRITE
	syscall
	; read pin
	xor rdi, rdi
	lea rsi, [rel entered_pin]
	mov rdx, 8
	mov rax, SYS_READ
	syscall
	; verify
	lea rsi, [rel correct_pin]
	lodsq
	mov rbx, rax
	lea rsi, [rel entered_pin]
	lodsq
	cmp rax, rbx
	je success
fail:
	xor rdi, rdi
	inc rdi
	lea rsi, [rel incorrect_msg]
	mov rdx, end_incorrect_msg
	sub rdx, rsi
	mov rax, SYS_WRITE
	syscall
	mov rdi, 1
	jmp end
success:
	xor rdi, rdi
	inc rdi
	lea rsi, [rel correct_msg]
	mov rdx, end_correct_msg
	sub rdx, rsi
	mov rax, SYS_WRITE
	syscall
	xor rdi, rdi
end:
	mov rax, SYS_EXIT
	syscall
	hlt
	leave
	ret

section .data
global welcome_msg
global correct_msg
global correct_pin
welcome_msg:
db "PIN CODE:",0xa,0
end_welcome_msg:
correct_msg:
db "CORRECT. The flag is HSGSSec{XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX}",0xa,0
end_correct_msg:
incorrect_msg:
db "INCORRECT!",0xa,0
end_incorrect_msg:
correct_pin:
dq 0xdeadbeef41424344
entered_pin:
dq 0
