import struct, logging
import goal as go, gadget as ga
import z3helper

PAGE_MASK = 0xfffffffffffff000
PROT_RWX = 7

class Scheduler(object):
  func_calling_convention = [ "rdi", "rsi", "rdx", "rcx", "r8", "r9" ]
  #syscall_calling_convention = [ "rdi", "rsi", "rdx", "r10", "r8", "r9" ]  # TODO cover the syscall case

  def __init__(self, gadgets, goal_resolver, level):
    logging.basicConfig(format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    self.logger = logging.getLogger(self.__class__.__name__)
    self.logger.setLevel(level)

    self.gadgets = gadgets
    self.solver = z3helper.Z3Helper()
    self.goal_resolver = goal_resolver
    self.goals = goal_resolver.get_goals()
    self.find_needed_gadgets()
    self.chain = self.chain_gadgets()

  def get_chain(self):
    return self.chain

  def find_load_stack_gadget(self, register_name):
    best = None
    for gadget in self.gadgets:
      if (type(gadget) == ga.LoadStack # It's a load from the stack (most likely a pop)
        and register_name == gadget.output.name # and it's for the correct register
        and (best == None or best.complexity() > gadget.complexity())): # and it's got a better complexity than the current one
          best = gadget
    return best

  def find_needed_gadgets(self):

    self.blocks = {}
    for goal in self.goals:
      if type(goal) == go.FunctionGoal:
        needed_args = self.func_calling_convention[0:len(goal.arguments)]
      else: # shellcode goal
        needed_args = self.func_calling_convention[0:4] # mprotect(addr, len, prot) or syscall(10, addr, len, prot)

      for arg_needed in needed_args:
        if arg_needed in self.blocks:
          continue

        gadget = self.find_load_stack_gadget(arg_needed)
        if gadget != None:
          self.blocks[arg_needed] = gadget
          self.logger.debug("Found LoadStack %s Gadget:\n%s\n", arg_needed, gadget)
          continue

        # TODO Synthesize gadgets for missing types and add them to self.blocks

  def ap(self, address):
    return struct.pack("Q", address)

  def create_function_chain(self, goal, next_address = 0x44444444):
    chain = ""
    prev_gadget = goal.address
    self.logger.info("Creating function chain for %s(%s) and finishing with a return to 0x%x", goal.name,
      ",".join([hex(x) for x in goal.arguments]), next_address)

    for i in range(len(goal.arguments)-1, -1, -1):
      arg = goal.arguments[i]
      reg = self.func_calling_convention[i]
      if not reg in self.blocks:
        msg = "No gadget found to set {} register during function call to {}".format(reg, goal.name)
        self.logger.critical(msg)
        raise RuntimeError(msg)

      gadget = self.blocks[reg]
      differences = self.solver.get_values(gadget.to_statements())

      arg_chain  = differences[reg + "_output"][1] * "A"
      arg_chain += self.ap(arg)
      arg_chain += (differences["rip_output"][1] - len(arg_chain)) * "B"
      arg_chain += self.ap(prev_gadget)
      arg_chain += (differences["rsp_output"][1] - len(arg_chain)) * "C"
      chain = arg_chain + chain

      prev_gadget = gadget.address

    chain = chain + self.ap(next_address)
    return (chain, prev_gadget)

  def create_shellcode_address_chain(self, goal):
    addresses = self.goal_resolver.resolve_functions(["mprotect", "syscall"])

    if addresses["mprotect"] != None:
      self.logger.info("Found mprotect, using to change shellcode permissions")
      mprotect_goal = go.FunctionGoal("mprotect", addresses["mprotect"], [goal.shellcode_address & PAGE_MASK, 0x10000, PROT_RWX])
      return self.create_function_chain(mprotect_goal, goal.shellcode_address)
    elif addresses["syscall"] != None:
      self.logger.info("Found syscall(), using it to call mprotect to change shellcode permissions")
      syscall_goal = go.FunctionGoal("syscall", addresses["syscall"], [10, goal.shellcode_address & PAGE_MASK, 0x10000, PROT_RWX])
      return self.create_function_chain(syscall_goal, goal.shellcode_address)
    else: # TODO add mmap/memcpy, mmap + rop memory writing, using syscalls instead of functions, and others ways to change memory protections
      pass

    raise RuntimeError("Failed with shellcode address goal")

  def chain_gadgets(self):
    chain = ""
    next_address = 0x4444444444444444
    for i in range(len(self.goals)-1, -1, -1):
      goal = self.goals[i]
      if type(goal) == go.FunctionGoal:
        goal_chain, next_address = self.create_function_chain(goal, next_address)
        self.logger.debug("Function call to %s's first gadget is at 0x%x", goal.name, next_address)
      elif type(goal) == go.ShellcodeAddressGoal:
        goal_chain, next_address = self.create_shellcode_address_chain(goal)
      elif type(goal) == go.ShellcodeGoal:
        # TODO implement putting the shellcode into memory
        pass # Shellcode goals end the chain

      chain = goal_chain + chain

    return self.ap(next_address) + chain

