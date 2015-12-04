import struct
import goal as go, gadget as ga
import z3helper

PAGE_MASK = 0xfffffffffffff000
PROT_RWX = 7

class Scheduler(object):
  func_calling_convention = [ "rdi", "rsi", "rdx", "rcx", "r8", "r9" ]
  #syscall_calling_convention = [ "rdi", "rsi", "rdx", "r10", "r8", "r9" ]  # TODO cover the syscall case

  def __init__(self, gadgets, goals):
    self.gadgets = gadgets
    self.solver = z3helper.Z3Helper()
    self.goals = goals
    self.find_needed_gadgets()
    self.chain = self.chain_gadgets()

  def get_chain(self):
    return self.chain

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

  def create_function_chain(self, goal, next_address = 0x44444444):
    chain = ""
    prev_gadget = goal.address
    for i in range(len(goal.arguments)-1, -1, -1):
      arg = goal.arguments[i]
      reg = self.func_calling_convention[i]
      gadget = self.blocks[reg]
      print "Setting arg %d to %x" % (i, arg)
      print gadget
      differences = self.solver.get_values(gadget.to_statements())

      arg_chain  = differences[reg + "_output"][1] * "A"
      arg_chain += struct.pack("Q", arg)
      arg_chain += (differences["rip_output"][1] - len(arg_chain)) * "B"
      arg_chain += struct.pack("Q", prev_gadget)
      arg_chain += (differences["rsp_output"][1] - len(arg_chain)) * "C"
      chain = arg_chain + chain

      prev_gadget = gadget.address

    chain = struct.pack("Q", prev_gadget) + chain + struct.pack("Q", next_address)
    return chain

  def create_shellcode_address_chain(self, goal):
    mprotect_goal = go.FunctionGoal("mprotect", goal.mprotect_address, [goal.shellcode_address & PAGE_MASK, 0x10000, PROT_RWX])
    mprotect_chain = self.create_function_chain(mprotect_goal, goal.shellcode_address)
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

      chain += goal_chain

    return chain
    # TODO chain to gather the blocks into function calls and goals







