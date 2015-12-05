import json, logging
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
        elffile = ELFFile(open(filename, 'r'))
        address = int(address, 16)
        self.file_list.append((elffile, address))

  def is_address(self, string):
    try: 
        int(string, 16)
        return True
    except ValueError:
        return False

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

  def resolve_function(self, name):
    for elffile, address in self.file_list:
      containers = [elffile.get_section_by_name('.symtab'), elffile.get_section_by_name('.dynsym'),
        self.get_dynamic_segment(elffile)]
      for container in containers:
        if container and (isinstance(container, SymbolTableSection) or isinstance(container, DynamicSegment)):
          symbol_address = self.find_symbol(elffile, address, container, name)
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
        fd = open(goal[1], "r")
        shellcode = fd.read()
        fd.close()
        self.goals.append(ShellcodeGoal(shellcode))
      else:
        raise RuntimeError("Unknown goal") 
        
  def get_goals(self):
    return self.goals


def create_from_arguments(filenames_and_addresses, goals, level = logging.WARNING):
  """Converts filenames and a set of goals into json for convience (aka, I'm too lazy to fix the constructor)"""
  files = []
  for (filename, address) in filenames_and_addresses:
    files.append('[ "{}", "0x{:x}" ]'.format(filename, address))

  json = '{ "files" : [ %s ], "goals" : %s }' % (",".join(files), str(goals).replace("'",'"'))
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

