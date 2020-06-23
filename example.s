section .text
global start
xorab:
	push    rbp
	mov     rbp, rsp
	mov     QWORD [rbp-8], rdi
	mov     QWORD [rbp-16], rsi
	mov     rax, QWORD [rbp-8]
	xor     rax, QWORD [rbp-16]
	pop     rbp
	ret
f:
	push    rbp
	mov     rbp, rsp
	sub     rsp, 16
	mov     QWORD [rbp-8], 5
	mov     QWORD [rbp-16], 7
	mov     rdx, QWORD [rbp-16]
	mov     rax, QWORD [rbp-8]
	mov     rsi, rdx
	mov     rdi, rax
	call    xorab
	leave
	ret
start:
	push    rbp
	mov     rbp, rsp
	call    f
	mov     eax, 0
	pop     rbp
	ret