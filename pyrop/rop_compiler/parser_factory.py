import cle_parser
import radare_parser
import pyelf_parser

def get_class_from_name(name):
  if name.lower().find("cle") != -1:
    return cle_parser.CleFinder
  elif name.lower().find("pyelf") != -1:
    return pyelf_parser.PyelfParser
  elif name.lower().find("radare") != -1:
    return radare_parser.RadareFinder
  raise RuntimeError("Unknown file parser: %s" % name)
