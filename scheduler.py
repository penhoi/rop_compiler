import goals

class Scheduler(object):

  def __init__(self, gadgets, goals):
    self.gadgets = gadgets
    self.goals = goals
    self.set_gadgets_needed()
    self.find_needed_gadgets()

  def find_needed_gadgets(self):
    func_calling_convention = [ "rdi", "rsi", "rdx", "rcx", "r8", "r9" ]
    #syscall_calling_convention = [ "rdi", "rsi", "rdx", "r10", "r8", "r9" ]  # TODO cover the syscall case

    self.blocks = {}
    for goal in self.goals:
      if type(goals.FunctionGoal):
        needed_args = func_calling_convention[0:len(goal.arguments)]
      else: # shellcode goal
        needed_args = func_calling_convention[0:3] # mprotect(addr, len, prot)
    
      for arg_needed in needed_args:
        if arg_needed in self.blocks:
          continue

        # TODO Find gadget and add it to self.blocks


