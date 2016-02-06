import cle_parser
import radare_parser
import pyelf_parser
import file_finder
import memory_finder

def get_parser_from_name(name = "cle"):
  if name.lower().find("cle") != -1:
    return cle_parser.CleParser
  elif name.lower().find("pyelf") != -1:
    return pyelf_parser.PyelfParser
  elif name.lower().find("radare") != -1:
    return radare_parser.RadareFinder
  elif name == None:
    default_parser()
  raise RuntimeError("Unknown file parser: %s" % name)

def default_parser():
  return cle_parser.CleParser

def get_finder_from_name(name = "file"):
  if name.lower().find("file") != -1:
    return file_finder.FileFinder
  elif name.lower().find("mem") != -1:
    return memory_finder.MemoryFinder
  elif name == None:
    default_finder()
  raise RuntimeError("Unknown gadget finder: %s" % name)

def default_finder():
  return file_finder.FileFinder
