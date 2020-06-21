SYS_EXIT equ 0x3c
SYS_READ equ 0x0
SYS_WRITE equ 0x1
SYS_OPEN equ 0x2
SYS_CLOSE equ 0x3
SYS_EXECVE equ 0x3b
SYS_SETREUID equ 0x71
section .text
global _start
global main
_start:
	call get_random_pin	
	call main
	mov rdi, rax
	mov rax, SYS_EXIT
	syscall
	hlt
get_random_pin:
	randomfd equ 8
	; get random pin
	push rbp; save previous stack base
	mov rbp, rsp
	sub rsp, 8 ; allocate stack for storing fd

	mov rax, SYS_OPEN
	lea rdi, [rel urandom] ; /dev/urandom
	xor rsi, rsi ; O_RDONLY
	xor rdx, rdx
	syscall

	mov [rbp-randomfd], rax ; saved the fd to the stack
	
	mov rdi, rax
	lea rsi, [rel correct_pin]
	mov rdx, 8
	mov rax, SYS_READ
	syscall

	mov rax, SYS_CLOSE
	mov rdi, [rbp-randomfd]
	syscall
	add rsp, 8 ; deallocate stack memory
	leave ; restore stack base
	ret
strlen:
	xor al, al
	mov rsi, rdi
	repne scasb
	sub rdi, rsi
	mov rax, rdi
	ret
puts:
	push rdi
	call strlen
	mov rdx, rax
	xor rdi, rdi
	pop rsi
	mov rax, SYS_WRITE
	syscall
	ret
gets:
	mov rsi, rdi
	xor rdi, rdi
	mov rdx, 1
	xor rcx, rcx
.gets_loop:
	mov rax, SYS_READ
	syscall
	cmp rax, 1
	jl .end_gets
	mov al, byte [rsi]
	cmp al, 0xa ; endline
	je .end_gets
	inc rsi
	inc rcx
	jmp .gets_loop
.end_gets:
	sub rsi, rcx
	mov rax, rsi
	ret
RTFS:
	push rbp
	mov rbp, rsp
	xor rdi, rdi
	xor rsi, rsi
	mov rax, SYS_SETREUID
	syscall	
	mov rax, 0x0068732f6e69622f ; /bin/sh\x00
	push rax
	xor rsi, rsi
	xor rdx, rdx
	mov rdi, rsp
	mov rax, SYS_EXECVE
	syscall
	add rsp, 8
	leave
	ret
main:
	entered_pin equ -0x20
	push rbp
	mov rbp, rsp
	sub rsp, 0x20 ; allocate stack to get user pin
	; Print welcome message
	mov rdi, welcome_msg
	call puts
	; read pin
	lea rdi, [rbp+entered_pin]
	call gets
	; verify pin	
	lea rsi, [rbp+entered_pin]
	lea rdi, [rel correct_pin]
	mov rcx, 0x20
	repe cmpsb
	je .success

.fail:
	mov rdi, incorrect_msg
	call puts
	mov rax, 1
	jmp .end
.success:
	mov rdi, correct_msg
	call puts
	xor rax, rax
.end:
	add rsp, 0x20 ; deallocate stack
	leave
	ret

section .data
welcome_msg:
db "PIN CODE:",0xa,0
end_welcome_msg:
correct_msg:
db "CORRECT",0xa,0
end_correct_msg:
incorrect_msg:
db "INCORRECT",0xa,0
end_incorrect_msg:
urandom:
db "/dev/urandom",0
correct_pin:
dq 0,0,0,0
