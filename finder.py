from capstone import *
from elftools.elf.elffile import ELFFile
from elftools.elf.constants import P_FLAGS
import logging

class Finder(object):

  MAX_GADGET_SIZE = 10

  def __init__(self, filename, base_address = 0, level = logging.WARNING):
    logging.basicConfig(format="%(asctime)s - " + " - %(name)s - %(levelname)s - %(message)s")           
    self.logger = logging.getLogger(self.__class__.__name__)                                                                    
    self.logger.setLevel(level)                                                                                          

    self.fd = open(filename, "rb")
    self.elffile = ELFFile(self.fd)
    self.base_address = base_address

  def __del__(self):
    self.fd.close()

  def find_gadgets(self):
    gadgets = []
    for segment in self.iter_executable_segments():
      gadgets.extend(self.get_gadgets_for_segment(segment))
    return gadgets

  def iter_executable_segments(self):
    for seg in self.elffile.iter_segments():
      if seg.header.p_flags & P_FLAGS.PF_X != 0:
        yield seg

  def get_gadgets_for_segment(self, segment):
    disassembler = Cs(CS_ARCH_X86, CS_MODE_64)
    gadgets = []

    for i in range(len(segment.data())):
      break #TODO finish this
      for j in range(1, MAX_GADGET_SIZE):
        begin = i - j
        if i - j < 0:
          begin = 0

        code = segment.data[begin:i] 
        address = self.base_address + segment.p_paddr + begin
        if self.base_address == 0 and segment.p_paddr == 0:
          self.logger.WARNING("No base address given for library or PIE executable.  Addresses may be wrong")
        for inst in md.disasm(code, address):
          print("0x%x:\t%s\t%s" %(inst.address, inst.mnemonic, inst.op_str))

    return gadgets

if __name__ == "__main__":
  import argparse

  parser = argparse.ArgumentParser(description="Run the gadget locator on the supplied binary") 
  parser.add_argument('target', type=str, help='The file (executable/library) to find gadgets in')
  parser.add_argument('-base_address', type=str, help='The address the file is loaded at.  Only needed for PIE/PIC binaries')
  args = parser.parse_args()

  finder = Finder(args.target, args.base_address)
  finder.find_gadgets()

