from elftools.elf.elffile import ELFFile
from elftools.elf.constants import P_FLAGS
from elftools.elf.sections import SymbolTableSection
from elftools.elf.dynamic import DynamicSegment
import file_parser
import logging, collections

class PyelfParser(file_parser.FileParser):
  """This class parses an ELF files using pyelftools"""

  def __init__(self, filename, base_address = 0, level = logging.WARNING):
    super(PyelfParser, self).__init__(filename, base_address, level)
    self.fd = open(filename, "rb")
    self.elffile = ELFFile(self.fd)

  def __del__(self):
    self.fd.close()

  def iter_executable_segments(self):
    """Any iterator that only returns the executable sections in the ELF file"""
    for seg in self.elffile.iter_segments():
      if seg.header.p_flags & P_FLAGS.PF_X != 0:
        yield seg

  def get_segment_bytes_address(self, seg):
    """Returns a segments bytes and the address of the segment"""
    return segment.data(), segment.header.p_addr

  def get_dynamic_segment(self, elffile):
    """Finds the dynamic segment in an ELFFile"""
    found = None
    for segment in elffile.iter_segments():
      if isinstance(segment, DynamicSegment):
        found = segment
    return found

  def get_symbol_address(self, name):
    containers = [self.elffile.get_section_by_name('.symtab'), self.elffile.get_section_by_name('.dynsym'),
      self.get_dynamic_segment(self.elffile)]
    for container in containers:
      if container and (isinstance(container, SymbolTableSection) or isinstance(container, DynamicSegment)):
        symbol_address = self.find_symbol(container, name)
        if symbol_address != None:
          return symbol_address
    return None

  def find_symbol(self, container, name):
    """Given an ELFFile and a section/segment, this function searches the ELFFile to determine the address of a function"""
    for symbol in container.iter_symbols():
      if symbol.name == name and symbol.entry.st_value != 0:
        if self.get_dynamic_segment(self.elffile) != None: # if the file has a dynamic section, it's probably ASLR
          return self.base_address + symbol.entry.st_value # so include the address.  Note, this isn't the best heuristic though.
        else:
          return symbol.entry.st_value # otherwise, the offset is absolute and we don't need it
    return None
