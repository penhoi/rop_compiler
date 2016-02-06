import math, struct, collections, logging, sys
import archinfo
import utils
import cPickle as pickle

def from_string(data, log_level = logging.WARNING, address_offset = None):
  gadgets_dict = pickle.loads(data)
  gadgets_list = [item for sublist in gadgets_dict.values() for item in sublist] # Flatten list of lists

  # Turn the names of the arch back into archinfo classes (Which aren't pickle-able)
  for gadget in gadgets_list:
    gadget.arch = archinfo.arch_from_id(gadget.arch)

  gl = GadgetList(gadgets_list, log_level)
  if address_offset != None:
    gl.adjust_base_address(address_offset)
  return gl

class GadgetList(object):

  def __init__(self, gadgets = None, log_level = logging.WARNING):
    self.setup_logging(log_level)

    self.arch = None
    self.gadgets = collections.defaultdict(list, {})
    self.gadgets_per_output = collections.defaultdict(lambda : collections.defaultdict(list, []), {})
    if gadgets != None:
      self.add_gadgets(gadgets)

  def tr(self, reg):
    return self.arch.translate_register_name(reg)

  def setup_logging(self, log_level):
    self.log_level = log_level
    logging.basicConfig(format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    self.logger = logging.getLogger(self.__class__.__name__)
    self.logger.setLevel(log_level)

  def to_string(self):
    """Turns the gadget list into a pickle'd object. This method transforms the gadget list in the process, and thus this instance
      should not be used afterwards."""
    for gadget in self.foreach():
      gadget.arch = gadget.arch.name
    return pickle.dumps(self.gadgets)

  def add_gadget(self, gadget):
    self.gadgets[gadget.__class__.__name__].append(gadget)
    self.gadgets_per_output[gadget.__class__.__name__][gadget.output].append(gadget)
    if type(self.arch) == type(None):
      self.arch = gadget.arch

  def add_gadgets(self, gadgets):
    for gadget in gadgets:
      self.add_gadget(gadget)

  def adjust_base_address(self, address_offset):
    for gadget in self.foreach():
      gadget.address += address_offset

  def copy_gadgets(self, gadget_list):
    for gadget in gadget_list.foreach():
      self.add_gadget(gadget)

  def foreach(self):
    for gadget_type, gadgets in self.gadgets.items():
      for gadget in gadgets:
        yield gadget

  def foreach_type(self, gadget_type, no_clobbers = None):
    for gadget in self.gadgets[gadget_type.__name__]:
      if no_clobbers == None or not gadget.clobbers_registers(no_clobbers):
        yield gadget

  def foreach_type_output(self, gadget_type, output, no_clobbers = None):
    for gadget in self.gadgets_per_output[gadget_type.__name__][output]:
      if no_clobbers == None or not gadget.clobbers_registers(no_clobbers):
        yield gadget

  def find_gadget(self, gadget_type, input_registers = None, output_register = None, no_clobber = None):
    """This method will find the best gadget (lowest complexity) given the search criteria"""
    best = best_complexity = None
    for gadget in self.foreach_type(gadget_type):
      if ((input_registers == None # Not looking for a gadget with a specific register as input
          or (gadget.inputs[0] == input_registers[0] # Only looking for one specific input
            and (len(gadget.inputs) == 1 or gadget.inputs[1] == input_registers[1]))) # Also looking to match the second input
        and (output_register == None or gadget.output == output_register) # looking to match the output
        and (no_clobber == None or not gadget.clobbers_registers(no_clobber)) # Can't clobber anything we need
        and (best == None or best_complexity > gadget.complexity())): # and it's got a better complexity than the current one
          best = gadget
          best_complexity = best.complexity()

    if best == None:
      return self.create_new_gadgets(gadget_type, input_registers, output_register, no_clobber)
    return best

  def find_load_stack_gadget(self, register, no_clobber = None):
    """This method finds the best gadget (lowest complexity) to load a register from the stack"""
    return self.find_gadget(LoadMem, [self.arch.registers['sp'][0]], register, no_clobber)

###########################################################################################################
## Synthesizing Gadgets ###################################################################################
###########################################################################################################

  def create_new_gadgets(self, gadget_type, inputs, output, no_clobbers):
    if hasattr(self, gadget_type.__name__):
      return getattr(self, gadget_type.__name__)(inputs, output, no_clobbers)
    return None

  def LoadMem(self, inputs, output, no_clobbers):
    gadget = self.LoadMemFromMoveReg(inputs, output, no_clobbers)
    if gadget == None:
      gadget = self.LoadMemFromLoadMemJump(inputs, output, no_clobbers)
    return gadget

  def LoadMemFromMoveReg(self, inputs, output, no_clobbers):
    best_move = best_load = None
    best_complexity = sys.maxint
    for move_gadget in self.foreach_type_output(MoveReg, output, no_clobbers):
      for load_mem in self.foreach_type_output(LoadMem, move_gadget.inputs[0], no_clobbers):
        if inputs == None or len(inputs) < 1 or load_mem.inputs[0] == inputs[0]:
          complexity = move_gadget.complexity() + load_mem.complexity()
          if complexity < best_complexity:
            best_complexity = complexity
            (best_move, best_load) = (move_gadget, load_mem)
    if best_move != None:
      self.logger.debug("Creating new LoadMem[{}] from: {}{}".format(self.tr(output), best_move, best_load))
      return CombinedGadget([best_move, best_load])
    return None

  def LoadMemFromLoadMemJump(self, inputs, output, no_clobbers):
    best_load_mem_jump = best_load_mem = None
    best_complexity = sys.maxint
    for load_mem_jump in self.foreach_type_output(LoadMemJump, output, no_clobbers):
      if not (inputs == None or len(inputs) < 1 or load_mem_jump.inputs[0] == inputs[0]):
        continue
      for load_mem in self.foreach_type_output(LoadMem, load_mem_jump.inputs[1], no_clobbers):
        complexity = load_mem_jump.complexity() + load_mem.complexity()
        if complexity < best_complexity:
          best_complexity = complexity
          (best_load_mem_jump, best_load_mem) = (load_mem_jump, load_mem)
    if best_load_mem_jump != None:
      self.logger.debug("Creating new LoadMem[{}] from: {} and {}".format(self.tr(output), best_load_mem_jump, best_load_mem))
      return CombinedGadget([best_load_mem, best_load_mem_jump])
    return None

###########################################################################################################
## Gadget Classess ########################################################################################
###########################################################################################################

class GadgetBase(object):
  def clobbers_register(self, reg):
    raise RuntimeError("Not Implemented")

  def clobbers_registers(self, regs):
    raise RuntimeError("Not Implemented")

  def uses_register(self, name):
    raise RuntimeError("Not Implemented")

  def complexity(self):
    raise RuntimeError("Not Implemented")

  def validate(self):
    raise RuntimeError("Not Implemented")

  def chain(self, next_address, input_value = None): 
    raise RuntimeError("Not Implemented")

class CombinedGadget(GadgetBase):
  """This class wraps multiple gadgets which are combined to create a single ROP primitive"""
  def __init__(self, gadgets):
    self.gadgets = gadgets
    self.arch = gadgets[0].arch
    self.address = gadgets[0].address

  def __str__(self):
    return "CombinedGadget([{}])".format(", ".join([str(g) for g in self.gadgets]))

  def complexity(self):
    return sum([g.complexity() for g in self.gadgets])

  def clobbers_register(self, reg):
    return any([g.clobbers_register(reg) for g in self.gadgets])

  def clobbers_registers(self, regs):
    return any([g.clobbers_registers(regs) for g in self.gadgets])

  def uses_register(self, name):
    return any([g.uses_register(name) for g in self.gadgets])

  def validate(self):
    return all([g.validate() for g in self.gadgets])

  def chain(self, next_address, input_value = None):
    types = [type(g) for g in self.gadgets]
    if types == [LoadMem, LoadMemJump]:
      chain = self.gadgets[0].chain(self.gadgets[1].address, next_address)
      chain += self.gadgets[1].chain(None, input_value)
      return chain

    chain = ""
    for i in range(len(self.gadgets)):
      next_gadget_address = next_address
      if i + 1 < len(self.gadgets):
        next_gadget_address = self.gadgets[i+1].address
      chain += self.gadgets[i].chain(next_gadget_address, input_value)
    return chain

class Gadget(GadgetBase):
  """This class wraps a set of instructions and holds the associated metadata that makes up a gadget"""

  def __init__(self, arch, address, inputs, output, params, clobber, stack_offset, ip_in_stack_offset):
    self.arch = arch
    self.address = address
    self.inputs = inputs
    self.output = output
    self.params = params
    self.clobber = clobber
    self.stack_offset = stack_offset
    self.ip_in_stack_offset = ip_in_stack_offset

  def __str__(self):
    output = ""
    if self.output != None:
      output = ", Output: {}".format(self.arch.translate_register_name(self.output))
    inputs = ", ".join([self.arch.translate_register_name(x) for x in self.inputs])
    if inputs != "":
      inputs = ", Inputs [{}]".format(inputs)
    clobber = ", ".join([self.arch.translate_register_name(x) for x in self.clobber])
    if clobber != "":
      clobber = ", Clobbers [{}]".format(clobber)
    params = ", ".join([hex(x) for x in self.params])
    if params != "":
      params = ", Params [{}]".format(params)
    ip = self.ip_in_stack_offset
    if self.ip_in_stack_offset != None:
      ip = "0x{:x}".format(self.ip_in_stack_offset)
    return "{}(Address: 0x{:x}, Complexity {}, Stack 0x{:x}, Ip {}{}{}{}{})".format(self.__class__.__name__,
      self.address, round(self.complexity(), 2), self.stack_offset, ip, output, inputs, clobber, params)

  def _is_stack_reg(self, reg):
    return reg == self.arch.registers['sp'][0]

  def clobbers_register(self, reg):
    """Check if the gadget clobbers the specified register"""
    for clobber in self.clobber:
      if clobber == reg:
        return True
    return self.output == reg

  def clobbers_registers(self, regs):
    """Check if the gadget clobbers any of the specified registers"""
    for reg in regs:
      if self.clobbers_register(reg):
        return True
    return False

  def uses_register(self, name):
    """Check if the gadget uses the specified register as input"""
    for an_input in self.inputs:
      if type(an_input) == Register and an_input.name == name:
        return True
    return self.clobbers_register(name) or self.output == name

  def complexity(self):
    """Return a rough complexity measure for a gadget that can be used to select the best gadget in a set.  Our simple formula
      is based on the number of clobbered registers, and if a normal return (i.e. with no immediate is used).  The stack decider
      helps to priorize gadgets that use less stack space (and thus can fit in smaller buffers)."""
    complexity = 0
    if self.ip_in_stack_offset == None:
      complexity += 2
    elif self.stack_offset - (self.arch.bits/8) != self.ip_in_stack_offset:
      complexity += 1

    if self.stack_offset < 0:
      complexity += 10
    elif self.stack_offset > 0:
      complexity += (math.log(self.stack_offset)/math.log(8))

    return len(self.clobber) + complexity

  def validate(self):
    """This method validates the inputs, output, and parameters with z3 to ensure it follows the gadget type's preconditions"""
    # TODO validate the gadget type with z3
    return True

  def chain(self, next_address, input_value = None): 
    """Default ROP Chain generation, uses no parameters"""
    chain = self.ip_in_stack_offset * "I"
    chain += utils.ap(next_address, self.arch)
    chain += (self.stack_offset - len(chain)) * "J"
    return chain

###########################################################################################################
## The various Gadget types ###############################################################################
###########################################################################################################

class Jump(Gadget):
  def chain(self, next_address = None, input_value = None): 
    return self.stack_offset * "H" # No parameters or IP in stack, just fill the stack offset

class MoveReg(Gadget):         pass
class LoadConst(Gadget):       pass

class LoadMem(Gadget):
  def chain(self, next_address, input_value = None): 
    chain = ""
    input_from_stack = self._is_stack_reg(self.inputs[0]) and input_value != None

    # If our input value is coming from the stack, and it's supposed to come before the next PC address, add it to the chain now
    if input_from_stack and (self.ip_in_stack_offset == None or self.params[0] < self.ip_in_stack_offset):
      chain += self.params[0] * "A"
      chain += utils.ap(input_value, self.arch)

    if self.ip_in_stack_offset != None:
      chain += (self.ip_in_stack_offset - len(chain)) * "B"
      chain += utils.ap(next_address, self.arch)

    # If our input value is coming from the stack, and it's supposed to come after the next PC address, add it to the chain now
    if input_from_stack and self.ip_in_stack_offset != None and self.params[0] > self.ip_in_stack_offset:
      chain += (self.params[0] - len(chain)) * "A"
      chain += utils.ap(input_value, self.arch)

    chain += (self.stack_offset - len(chain)) * "C"
    return chain

class StoreMem(Gadget):        pass
class Arithmetic(Gadget):      pass
class ArithmeticLoad(Gadget):  pass
class ArithmeticStore(Gadget): pass

# Split up the Arithmetic gadgets, so they're easy to search for when you are searching for a specific one
class AddGadget(Arithmetic):   pass
class SubGadget(Arithmetic):   pass
class MulGadget(Arithmetic):   pass
class AndGadget(Arithmetic):   pass
class OrGadget(Arithmetic):    pass
class XorGadget(Arithmetic):   pass

# Split up the Arithmetic Load gadgets, so they're easy to search for when you are searching for a specific one
class LoadAddGadget(ArithmeticLoad):   pass
class LoadSubGadget(ArithmeticLoad):   pass
class LoadMulGadget(ArithmeticLoad):   pass
class LoadAndGadget(ArithmeticLoad):   pass
class LoadOrGadget(ArithmeticLoad):    pass
class LoadXorGadget(ArithmeticLoad):   pass

# Split up the Arithmetic Store gadgets, so they're easy to search for when you are searching for a specific one
class StoreAddGadget(ArithmeticStore):   pass
class StoreSubGadget(ArithmeticStore):   pass
class StoreMulGadget(ArithmeticStore):   pass
class StoreAndGadget(ArithmeticStore):   pass
class StoreOrGadget(ArithmeticStore):    pass
class StoreXorGadget(ArithmeticStore):   pass

# The Loads memory then jumps to a register
class LoadMemJump(LoadMem): pass



if __name__ == "__main__":
  def x(a, r):
    return a.registers[r][0]

  class FakeIrsb:
    def __init__(self, arch):
      self._addr = 0x40000
      self.arch = arch

  # A simple set of tests to ensure we can correctly synthesize some example gadgets
  amd64 = archinfo.ArchAMD64
  mips = archinfo.ArchMIPS64
  ppc = archinfo.ArchPPC32
  arm = archinfo.ArchARM

  rax, rbx, rsp = x(amd64,'rax'), x(amd64,'rbx'), x(amd64,'rsp')

  tests = {
    amd64 : {
      (LoadMem, (), rax, ()) : GadgetList([
        MoveReg(archinfo.ArchAMD64(), FakeIrsb(amd64), [rbx], rax, [], [], 8, 4),
        LoadMem(archinfo.ArchAMD64(), FakeIrsb(amd64), [rsp], rbx, [], [], 8, 4)
      ], logging.DEBUG),
      (LoadMem, (rsp,), rax, ()) : GadgetList([
        LoadMemJump(archinfo.ArchAMD64(), FakeIrsb(amd64), [rsp, rbx], rax, [], [], 8, None),
        LoadMem(archinfo.ArchAMD64(),     FakeIrsb(amd64), [rsp],      rbx, [], [], 8, 4)
      ], logging.DEBUG)
    },
    mips: {
    },
    ppc : {
    },
    arm : {
    }
  }
  import sys
  if len(sys.argv) > 1:
    arches = { "AMD64" : archinfo.ArchAMD64, "MIPS" : archinfo.ArchMIPS64, "PPC" : archinfo.ArchPPC32, "ARM" : archinfo.ArchARM}
    arch = arches[sys.argv[1].upper()]
    tests = { arch : tests[arch] }

  fail = False
  for arch, arch_tests in tests.items():
    print "\n{} Tests:".format(arch.name)

    for ((desired_type, inputs, output, no_clobbers), gadget_list) in arch_tests.items():
      result_gadget = gadget_list.create_new_gadgets(desired_type, inputs, output, no_clobbers)
      if result_gadget == None: # If we didn't get the gadget we want
        fail = True
        print "\nCouldn't create the gadget {}({}) from:".format(desired_type.__name__,arch().translate_register_name(output))
        print "\n".join(["\n".join([str(g) for g in gl]) for t,gl in gadget_list.gadgets.items()])

  if fail:
    print "\nFAILURE!!! One or more incorrectly synthesized gadgets"
  else:
    print "\nSUCCESS, all gadgets correctly synthesized"

