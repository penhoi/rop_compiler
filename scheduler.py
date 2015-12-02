import goal as go, gadget as ga

PAGE_MASK = 0xfffffffffffff000
PROT_RWX = 7

class Scheduler(object):

  func_calling_convention = [ "rdi", "rsi", "rdx", "rcx", "r8", "r9" ]
  #syscall_calling_convention = [ "rdi", "rsi", "rdx", "r10", "r8", "r9" ]  # TODO cover the syscall case

  def __init__(self, gadgets, goals):
    self.gadgets = gadgets
    self.goals = goals
    self.find_needed_gadgets()
    self.chain_gadgets()

  def find_load_stack_gadget(self, register_name):
    for gadget in self.gadgets:
      if gadget.gadget_type == ga.GadgetTypes.LOAD_STACK and register_name in gadget.output_register_names(): # best option
        return gadget
    return None

  def find_needed_gadgets(self):

    self.blocks = {}
    for goal in self.goals:
      if type(goal) == go.FunctionGoal:
        needed_args = self.func_calling_convention[0:len(goal.arguments)]
      else: # shellcode goal
        needed_args = self.func_calling_convention[0:3] # mprotect(addr, len, prot)

      for arg_needed in needed_args:
        if arg_needed in self.blocks:
          continue

        gadget = self.find_load_stack_gadget(arg_needed)
        if gadget != None:
          self.blocks[arg_needed] = gadget
          continue

        # TODO Synthesize gadgets for missing types and add them to self.blocks

    for (name, gadget) in self.blocks.items():
      print name, gadget

  def create_function_chain(self, goal, next_address = "XXXX"):
    for i in range(len(goal.arguments)):
      arg = goal.arguments[i]
      gadget = self.blocks[self.func_calling_convention[i]]
      print arg, gadget
      # TODO Transform choosen gadget into rop chain

  def create_shellcode_address_chain(self, goal):
    mprotect_goal = go.FunctionGoal("mprotect", goal.mprotect_address, [goal.shellcode_address & PAGE_MASK, 0x10000, PROT_RWX])
    mprotect_chain = self.create_function_chain(mprotect_goal)
    return mprotect_chain

  def chain_gadgets(self):
    chain = ""
    for goal in self.goals:
      if type(goal) == go.FunctionGoal:
        goal_chain = self.create_function_chain(goal)
      elif type(goal) == go.ShellcodeAddressGoal:
        goal_chain = self.create_shellcode_address_chain(goal)
      elif type(goal) == go.ShellcodeGoal:
        pass # TODO implement putting the shellcode into memory

    # TODO chain to gather the blocks into function calls and goals







