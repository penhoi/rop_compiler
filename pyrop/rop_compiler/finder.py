import archinfo
import logging, collections
import factories

class Finder(object):
  """This class parses a file to obtain any gadgets inside their executable sections"""

  """The maximum size in bytes of a gadget to look for"""
  MAX_GADGET_SIZE = { archinfo.ArchX86 : 10, archinfo.ArchAMD64 : 10, archinfo.ArchMIPS64 : 20, archinfo.ArchMIPS32 : 20,
    archinfo.ArchPPC32 : 20, archinfo.ArchPPC64 : 20, archinfo.ArchARM : 20 }

  def __init__(self, name, arch, base_address = 0, level = logging.WARNING):
    logging.basicConfig(format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    self.logger = logging.getLogger(self.__class__.__name__)
    self.logger.setLevel(level)
    self.level = level

    self.base_address = base_address
    self.arch = arch
    self.name = name

  def find_gadgets(self):
    """Finds gadgets in the specified file"""
    raise RuntimeError("Not Implemented")

if __name__ == "__main__":
  import argparse

  parser = argparse.ArgumentParser(description="Run the gadget locator on the supplied binary")
  parser.add_argument('filename', type=str, default=None, help='The file (executable/library) to load gadgets from')
  parser.add_argument('-arch', type=str, default="AMD64", help='The architecture of the binary')
  parser.add_argument('-finder_type', type=str, default="mem", help='The type of gadget finder (memory, file)')
  parser.add_argument('-o', type=str, default=None, help='File to write the gadgets to')
  parser.add_argument('-parser_type', type=str, default="cle", help='The type of file parser (cle, pyelf, radare)')
  parser.add_argument('-v', required=False, action='store_true', help='Verbose mode')
  args = parser.parse_args()

  finder_type = factories.get_finder_from_name(args.finder_type)
  logging_level = logging.DEBUG if args.v else logging.WARNING
  finder = finder_type(args.filename, archinfo.arch_from_id(args.arch).__class__, 0, logging_level, args.parser_type)
  gadget_list = finder.find_gadgets()

  if args.o == None:
    for gadget in gadget_list.foreach():
      print gadget
  else:
    fd = open(args.o, "w")
    fd.write(gadget_list.to_string())
    fd.close()

