from elftools.elf.elffile import ELFFile
from elftools.elf.constants import P_FLAGS
import archinfo
import logging, collections

import classifier as cl, gadget as ga, finder

class MemoryFinder(finder.Finder):
  """This class parses a file to obtain any gadgets inside their executable sections"""

  def __init__(self, name, arch, base_address = 0, level = logging.WARNING, parser_type = None):
    super(MemoryFinder, self).__init__(name, arch, base_address, level, parser_type)
    self.fd = open(name, "rb")
    self.elffile = ELFFile(self.fd)

  def __del__(self):
    self.fd.close()

  def find_gadgets(self):
    """Iterates over the defined files and return any gadgets"""
    gadget_list = ga.GadgetList(log_level = self.level)
    for segment in self.parser.iter_executable_segments():
      self.get_gadgets_for_segment(segment, gadget_list)
    self.logger.debug("Found %d gadgets", len([x for x in gadget_list.foreach()]))
    return gadget_list

  def get_gadgets_for_segment(self, segment, gadget_list):
    """Iteratively step through an executable section looking for gadgets at each address"""
    data, seg_address = self.parser.get_segment_bytes_address(segment)
    if self.base_address == 0 and seg_address == 0:
      self.logger.warning("No base address given for library or PIE executable.  Addresses may be wrong")

    classifier = cl.GadgetClassifier(self.arch, self.level)
    for i in range(0, len(data), self.STEP[self.arch]):
      end = i + self.MAX_GADGET_SIZE[self.arch]
      code = data[i:end]
      address = self.base_address + seg_address + i
      gadget_list.add_gadgets(classifier.create_gadgets_from_instructions(code, address))

if __name__ == "__main__":
  import argparse

  parser = argparse.ArgumentParser(description="Run the gadget locator on the supplied binary")
  parser.add_argument('-target', type=str, default=None, help='The file (executable/library) to find gadgets in')
  parser.add_argument('-gadgets_file', type=str, default=None, help='The file (executable/library) to find gadgets in')
  parser.add_argument('-base_address', type=str, default="0", help='The address the file is loaded at (in hex). Only needed'
    + ' for PIE/PIC binaries.  When creating a reusable gadgets file, do not specify')
  parser.add_argument('-arch', type=str, default="AMD64", help='The architecture of the binary')
  parser.add_argument('-v', required=False, action='store_true', help='Verbose mode')
  parser.add_argument('-o', type=str, default=None, help='File to write the gadgets to')
  args = parser.parse_args()

  finder = Finder(args.target, args.gadgets_file, archinfo.arch_from_id(args.arch).__class__, int(args.base_address, 16), logging.DEBUG if args.v else logging.WARNING)
  gadget_list = finder.find_gadgets()

  if args.o == None:
    for gadget in gadget_list.foreach():
      print gadget, gadget.complexity()
  else:
    fd = open(args.o, "w")
    fd.write(gadget_list.to_string())
    fd.close()

