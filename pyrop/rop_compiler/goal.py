# This file wraps the goal interface, i.e. how you tell the ROP compiler what you want your ROP chain to do.
import json, logging, binascii, factories

class Goal(object):
  """This class is the parent Goal class, where any common methods can be placedd"""
  pass

class FunctionGoal(Goal):
  """This class represents the goal of calling a specific function with a set of arguments"""
  def __init__(self, name, address, arguments):
    self.name = name
    self.address = address
    self.arguments = arguments

  def __str__(self):
    return "{}({}) == 0x{:x}".format(self.name, ",".join([str(x) for x in self.arguments]), self.address)

class ExecveGoal(FunctionGoal):
  """This class represents a call to execve to start another program"""

  def __init__(self, name, address, arguments):
    super(ExecveGoal, self).__init__(name, address, [])
    for arg in arguments:
      if type(arg) not in [int, long]:
        arg = str(arg)
      self.arguments.append(arg)

class ShellcodeGoal(Goal):
  """This class reprsents the goal of executing the given shellcode that doesn't already exist in memory"""
  def __init__(self, shellcode):
    self.shellcode = shellcode

  def __str__(self):
    return "shellcode[{}]".format(len(self.shellcode))

class ShellcodeAddressGoal(Goal):
  """This class reprsents the goal of executing the given shellcode that already exist in memory"""
  def __init__(self, shellcode_address):
    self.shellcode_address = shellcode_address

  def __str__(self):
    return "shellcode[0x{:x}]".format(self.shellcode_address)

class GoalResolver(object):
  """This class converts a list of options and config information about the libraries and target binaries into a set of goals
    and metadata for use during ROP chain generation

    The following goal types are defined.
      function - This goal attempts to build a ROP chain that will call the specified function.  The first parameter should be
        the name (or address) of the desired function.  Any arguments to the function are specified in the remaining parameters.
        Any number of function calls can be specified.
      shellcode_file - This goal reads shellcode from a file and then attempts to build a ROP chain to execute it.  The first
        parameter should be the filename of the file that contains the shellcode.  This goal must be the last one in the set of
        goals.
      shellcode_hex - This goal reads accepts shellcode as its first parameter and attempts to build a ROP chain to execute it.
        This goal must be the last one in the set of goals.
      shellcode - This goal is used to build a ROP chain to execute a set of shellcode that's already within the address space
        of the target program (but not necessarily with the right memory permissions).  This goal must be the last one in the
        set of goals.
      execve - This goal calls the function execve, while setting up the arguments appropriately to call the program specified
  """

  def __init__(self, file_handler, goal_list, level = logging.WARNING):
    logging.basicConfig(format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    self.logger = logging.getLogger(self.__class__.__name__)
    self.logger.setLevel(level)
    self.file_handler = file_handler
    self.goal_list = goal_list
    self.interpret_goals()

  def is_address(self, string):
    """Determines if the specified string is a properly formated hex address"""
    try:
        int(string, 16)
        return True
    except ValueError:
        return False

  def get_function_address(self, name):
    if self.is_address(name):
      address = int(name, 16)
    else:
      address = self.file_handler.get_symbol_address(str(name))
    return address

  def interpret_goals(self):
    """This method converts the goals json to a list of Goal classes"""

    self.goals = []
    for goal in self.goal_list:
      if goal[0] == "function":
        address = self.get_function_address(goal[1])
        self.goals.append(FunctionGoal(goal[1], address, goal[2:]))
        self.logger.debug("Created a FunctionGoal to {} (0x{:x}) with arguments {}".format(goal[1], address, goal[2:]))
      elif goal[0] == "execve":
        address = self.get_function_address(goal[0])
        self.goals.append(ExecveGoal(goal[0], self.get_function_address(goal[0]), goal[1:]))
        self.logger.debug("Created a ExecveGoal to call execve (0x{:x}) with arguments {}".format(address, goal[1:]))
      elif goal[0] == "shellcode":
        shellcode_address = int(goal[1], 16)
        self.goals.append(ShellcodeAddressGoal(shellcode_address))
        self.logger.debug("Created a ShellcodeAddressGoal to jump to shellcode at address 0x{:x}".format(shellcode_address))
      elif goal[0] == "shellcode_file":
        shellcode = self.get_contents(goal[1])
        self.goals.append(ShellcodeGoal(shellcode))
        self.logger.debug("Created a ShellcodeGoal to run {} bytes of shellcode".format(len(shellcode)))
      elif goal[0] == "shellcode_hex":
        shellcode = binascii.unhexlify(goal[1])
        self.goals.append(ShellcodeGoal(shellcode))
        self.logger.debug("Created a ShellcodeGoal to run {} bytes of shellcode".format(len(shellcode)))
      else:
        raise RuntimeError("Unknown goal")

  def get_goals(self):
    """Returns the set of goals that were given during class creation"""
    return self.goals
