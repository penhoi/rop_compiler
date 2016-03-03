import struct
import z3

def ap(address, arch):
  """Packs an address into a string. ap is short for Address Pack"""
  formats = { 32 : "I", 64 : "Q" }
  endian = { 'Iend_BE' : '>', 'Iend_LE' : '<' }
  if type(address) == str: # Assume already packed
    return address
  if address < 0:
    address = (2 ** arch.bits) + address
  address = mask(address, arch.bits) # Mask it so struct.pack doesn't complain (probably not the best idea, but it's the

  return struct.pack(endian[arch.memory_endness] + formats[arch.bits], address) # caller's problem to check their arguments before calling)

def get_contents(filename):
  """Convenience method that reads a file on disk and returns the contents"""
  fd = open(filename, "r")
  contents = fd.read()
  fd.close()
  return contents

def get_mask(size = 64):
  return (2 ** size) - 1

def mask(value, size = 64):
  return value & get_mask(size)

def z3_get_memory(memory, address, size, arch):
  value = z3.Select(memory, address)
  for i in range(1, size/8):
    new_byte = z3.Select(memory, address + i)
    if arch.memory_endness == 'Iend_LE':
      value = z3.Concat(new_byte, value)
    else:
      value = z3.Concat(value, new_byte)
  return value

def z3_set_memory(memory, address, value, arch):
  size = value.size()
  num_bytes = size/8
  new_memory = memory
  for i in range(0, num_bytes):
    if arch.memory_endness == 'Iend_LE':
      upper = ((i + 1) * 8) - 1
    else:
      upper = ((num_bytes - i) * 8) - 1
    new_memory = z3.Store(new_memory, address + i, z3.Extract(upper, upper - 7, value))
  return new_memory

