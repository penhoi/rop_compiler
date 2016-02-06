import logging, collections, os
import file_parser
import cle

class CleParser(file_parser.FileParser):
  """This class parses an executable file using radare"""

  def __init__(self, filename, base_address = 0, level = logging.WARNING):
    super(CleParser, self).__init__(filename, base_address, level)
    self.ld = cle.Loader(filename)

  def iter_executable_segments(self):
    """Any iterator that only returns the executable sections in the ELF file"""
    for seg in self.ld.main_bin.segments:
      if seg.is_executable:
        yield seg

  def get_segment_bytes_address(self, seg):
    """Returns a segments bytes and the address of the segment"""
    return ''.join(self.ld.memory.read_bytes(seg.vaddr, seg.memsize)), seg.vaddr

  def get_symbol_address(self, name, recurse_with_imp = True):
    """Returns the address for a symbol, or None if the symbol can't be found"""
    return self.ld.main_bin.get_symbol(name).rebased_addr
