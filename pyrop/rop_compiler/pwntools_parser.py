import logging, collections, os
import file_parser
from pwn import *

class PwntoolsParser(file_parser.FileParser):
  """This class parses an executable file using radare"""

  def __init__(self, filename, base_address = 0, level = logging.WARNING):
    super(PwntoolsParser, self).__init__(filename, base_address, level)
    self.elf = ELF(filename)
    if base_address != 0:
      self.elf.address = base_address

  def iter_executable_segments(self):
    """Any iterator that only returns the executable sections in the ELF file"""
    for seg in self.elf.executable_segments:
      yield seg

  def get_segment_bytes_address(self, seg):
    """Returns a segments bytes and the address of the segment"""
    return seg.data(), seg.header.p_vaddr + self.base_address # vaddr doesn't respect elf.address

  def get_symbol_address(self, name, recurse_with_imp = True):
    """Returns the address for a symbol, or None if the symbol can't be found"""
    if name in self.elf.symbols:
      return self.elf.symbols[name]
    return None

  def get_writable_memory(self):
    return self.elf.get_section_by_name('.data').header.sh_addr + self.base_address # sh_addr doesn't respect elf.address

  def find_symbol_in_got(self, name):
    if name in self.elf.got:
      return self.elf.got[name]
    return None
