import struct

def ap(address, arch):
  """Packs an address into a string. ap is short for Address Pack"""
  formats = { 32 : "I", 64 : "Q" }
  if type(address) == str: # Assume already packed
    return address
  if address < 0:
    address = (2 ** arch.bits) + address
  address = mask(address, arch.bits) # Mask it so struct.pack doesn't complain (probably not the best idea, but it's the
  return struct.pack(formats[arch.bits], address) # caller's problem to check their arguments before calling)

def get_contents(filename):
  """Convenience method that reads a file on disk and returns the contents"""
  fd = open(filename, "r")
  contents = fd.read()
  fd.close()
  return contents

def mask(value, size = 64):
  return value & ((2 ** size) - 1)
