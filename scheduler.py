import goal as go, gadget as ga

class Scheduler(object):

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
    func_calling_convention = [ "rdi", "rsi", "rdx", "rcx", "r8", "r9" ]
    #syscall_calling_convention = [ "rdi", "rsi", "rdx", "r10", "r8", "r9" ]  # TODO cover the syscall case

    self.blocks = {}
    for goal in self.goals:
      if type(goal) == go.FunctionGoal:
        needed_args = func_calling_convention[0:len(goal.arguments)]
      else: # shellcode goal
        needed_args = func_calling_convention[0:3] # mprotect(addr, len, prot)

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

  def chain_gadgets(self):
    pass
    # TODO chain to gather the blocks into function calls and goals
