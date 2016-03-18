
def get_parser_from_name(name = "cle"):
  if name == None:
    return default_parser()
  elif name.lower().find("cle") != -1:
    return default_parser()
  elif name.lower().find("pwn") != -1:
    import pwntools_parser
    return pwntools_parser.PwntoolsParser
  elif name.lower().find("pyelf") != -1:
    import pyelf_parser
    return pyelf_parser.PyelfParser
  elif name.lower().find("radare") != -1:
    import radare_parser
    return radare_parser.RadareParser
  raise RuntimeError("Unknown file parser: %s" % name)

def default_parser():
    import cle_parser
    return cle_parser.CleParser

def get_finder_from_name(name = "file"):
  if name == None:
    return default_finder()
  elif name.lower().find("mem") != -1:
    return default_finder()
  elif name.lower().find("file") != -1:
    import file_finder
    return file_finder.FileFinder
  raise RuntimeError("Unknown gadget finder: %s" % name)

def default_finder():
  import memory_finder
  return memory_finder.MemoryFinder
