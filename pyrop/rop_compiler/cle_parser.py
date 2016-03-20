import logging, collections, os
import file_parser
import cle

class CleParser(file_parser.FileParser):
  """This class parses an executable file using cle"""

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
    return ''.join(self.ld.main_bin.memory.read_bytes(seg.vaddr, seg.memsize)), seg.vaddr + self.base_address

  def get_symbol_address(self, name, recurse_with_imp = True):
    """Returns the address for a symbol, or None if the symbol can't be found"""
    symbol = self.ld.main_bin.get_symbol(name)
    if symbol != None:
      if symbol.rebased_addr == 0: # For some symbols, it doesn't look in the plt.  Fix that up here.
        return self.ld.main_bin._plt[name] + self.base_address
      return symbol.addr + self.base_address
    return None

  def get_writable_memory(self):
    return self.ld.main_bin.sections_map['.data'].vaddr + self.base_address

  def find_symbol_in_got(self, name):
    return self.ld.find_symbol_got_entry(name)
