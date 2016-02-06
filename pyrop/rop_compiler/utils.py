import struct

def ap(address, arch):
  """Packs an address into a string. ap is short for Address Pack"""
  formats = { 32 : "I", 64 : "Q" }
  if type(address) == str: # Assume already packed
    return address
  if address < 0:
    address = (2 ** arch.bits) + address
  return struct.pack(formats[arch.bits], address)

def get_contents(filename):
  """Convenience method that reads a file on disk and returns the contents"""
  fd = open(filename, "r")
  contents = fd.read()
  fd.close()
  return contents

