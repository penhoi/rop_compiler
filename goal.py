import json, logging, binascii
from elftools.elf.elffile import ELFFile
from elftools.elf.constants import P_FLAGS
from elftools.elf.sections import SymbolTableSection
from elftools.elf.dynamic import DynamicSegment

class Goal(object): # parent goal object
  pass

class FunctionGoal(Goal):
  def __init__(self, name, address, arguments):
    self.name = name
    self.address = address
    self.arguments = arguments

  def __str__(self):
    return "{}({}) == 0x{:x}".format(self.name, ",".join([str(x) for x in self.arguments]), self.address) 

class ShellcodeGoal(Goal):
  def __init__(self, shellcode):
    self.shellcode = shellcode

  def __str__(self):
    return "shellcode[{}]".format(len(self.shellcode))

class ShellcodeAddressGoal(Goal):
  def __init__(self, shellcode_address):
    self.shellcode_address = shellcode_address

  def __str__(self):
    return "shellcode[0x{:x}]".format(self.shellcode_address)

class GoalResolver(object):

  def __init__(self, goal_json, level = logging.WARNING):
    logging.basicConfig(format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    self.logger = logging.getLogger(self.__class__.__name__)
    self.logger.setLevel(level)

    self.json = json.loads(goal_json)
    self.resolve_file_list()
    self.interpret_goals()

  def resolve_file_list(self):
    self.file_list = []
    if 'files' in self.json:
      for (filename, address) in self.json['files']:
        if filename != "":
          elffile = ELFFile(open(filename, 'r'))
          address = int(address, 16)
          self.file_list.append((elffile, address))

    self.libraries = []
    if 'libraries' in self.json:
      for filename in self.json['libraries']:
        if filename != "":
          self.libraries.append(ELFFile(open(filename, 'r')))

  def is_address(self, string):
    try: 
        int(string, 16)
        return True
    except ValueError:
        return False

  def get_writable_memory(self):
    for elffile, address in self.file_list:
      data_section = elffile.get_section_by_name(".data")
      return data_section.header.sh_addr
    raise RuntimeError("Couldn't find a .data section when looking for writable memory")

  def get_dynamic_segment(self, elffile):
    for segment in elffile.iter_segments():
      if isinstance(segment, DynamicSegment):
        found = segment
    return found

  def find_symbol(self, elffile, address, container, name):
    for symbol in container.iter_symbols():
      if symbol.name == name and symbol.entry.st_value != 0:
        if self.get_dynamic_segment(elffile) != None: # if the file has a dynamic section, it's probably ASLR
          return address + symbol.entry.st_value # so include the address
        else:
          return symbol.entry.st_value # otherwise, the offset is absolute and we don't need it
    return None

  def resolve_function_in_file(self, elffile, address, name):
    containers = [elffile.get_section_by_name('.symtab'), elffile.get_section_by_name('.dynsym'),
      self.get_dynamic_segment(elffile)]
    for container in containers:
      if container and (isinstance(container, SymbolTableSection) or isinstance(container, DynamicSegment)):
        symbol_address = self.find_symbol(elffile, address, container, name)
        if symbol_address != None:
          return symbol_address
    return None

  def resolve_function(self, name):
    for elffile, address in self.file_list:
      symbol_address = self.resolve_function_in_file(elffile, address, name)
      if symbol_address != None:
        return symbol_address
    raise RuntimeError("Could not resolve the address of function {}.".format(name))

  def resolve_functions(self, names):
    addresses = {}
    for name in names:
      try:
        address = self.resolve_function(name)
      except:
        address = None
      addresses[name] = address
    return addresses

  def get_contents(self, filename):
    fd = open(filename, "r")
    contents = fd.read()
    fd.close()
    return contents

  def interpret_goals(self):
    self.goals = []
    for goal in self.json['goals']:
      if goal[0] == "function":
        address = goal[1]
        if self.is_address(address):
          address = int(address, 16)
        else:
          address = self.resolve_function(address)

        self.goals.append(FunctionGoal(goal[1], address, goal[2:]))
      elif goal[0] == "shellcode":
        shellcode_address = int(goal[1], 16)
        self.goals.append(ShellcodeAddressGoal(shellcode_address))
      elif goal[0] == "shellcode_file":
        shellcode = self.get_contents(goal[1])
        self.goals.append(ShellcodeGoal(shellcode))
      elif goal[0] == "shellcode_hex":
        shellcode = binascii.unhexlify(goal[1])
        self.goals.append(ShellcodeGoal(shellcode))
      else:
        raise RuntimeError("Unknown goal") 

  def symbol_number(self, elffile, name):
    symbols_section = elffile.get_section_by_name('.dynsym')
    for i in range(0, symbols_section.num_symbols()):
      if symbols_section.get_symbol(i).name == name:
        return i
    return None

  def resolve_symbol_from_got(self, base_name, target_name):
    """Gets the offset from one symbol to another in a library, and the address of the symbol in the GOT.  This info can be
      used to determine the target symbol if one can read the given symbol in the GOT."""

    # First, get the address of the base in the GOT
    main_binary = self.file_list[0][0]
    got_addr = main_binary.get_section_by_name(".got").header.sh_addr
    symbol_num = self.symbol_number(main_binary, base_name)
    if symbol_num == None:
      return (None, None)
    symbol_in_got = got_addr + 0x20 + ((symbol_num-1) * 8)

    # Now, get the offset from the base to the target in libc
    for lib in self.libraries:
      base_in_libc = self.resolve_function_in_file(lib, 0, base_name)
      target_in_libc = self.resolve_function_in_file(lib, 0, target_name)
      if base_in_libc != None and target_in_libc != None:
        break

    if base_in_libc == None and target_in_libc == None:
      return (None, None)

    return symbol_in_got, (target_in_libc - base_in_libc)

  def get_goals(self):
    return self.goals


def create_from_arguments(filenames_and_addresses, libraries, goals, level = logging.WARNING):
  """Converts filenames and a set of goals into json for convience (aka, I'm too lazy to fix the constructor)"""
  files = []
  for (filename, address) in filenames_and_addresses:
    files.append('[ "{}", "0x{:x}" ]'.format(filename, address))

  json = '{ "files" : [ %s ], "libraries" : [ "%s" ], "goals" : %s }' % (",".join(files), 
    '","'.join(libraries), str(goals).replace("'",'"'))
  return GoalResolver(json, level)

if __name__ == "__main__":
  import argparse

  parser = argparse.ArgumentParser(description="Resolve function names and interpret the goals")
  parser.add_argument('goal_file', type=str, help='A file describing the goals (in json)')
  parser.add_argument('-v', required=False, action='store_true', help='Verbose mode')
  args = parser.parse_args()

  fd = open(args.goal_file, 'r')
  goal_json = fd.read()
  fd.close()

  goal_resolver = GoalResolver(goal_json, logging.DEBUG if args.v else logging.WARNING)
  goals = goal_resolver.get_goals()

  for goal in goals:
    print goal
