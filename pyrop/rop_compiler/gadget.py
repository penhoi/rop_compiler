import math, struct, collections, logging, sys
import archinfo
import z3
import cPickle as pickle
import utils, extra_archinfo

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
    type_name = self.gadget_type_name(gadget.__class__)
    self.gadgets[type_name].append(gadget)

    output = None
    if len(gadget.outputs) > 0:
      output = gadget.outputs[0]
    self.gadgets_per_output[type_name][output].append(gadget)
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

  def gadget_type_name(self, gadget_type):
    """Get the gadget class name without any of the leading module names"""
    return gadget_type.__name__.split(".")[-1]

  def foreach(self):
    for gadget_type, gadgets in self.gadgets.items():
      for gadget in gadgets:
        yield gadget

  def foreach_type(self, gadget_type, no_clobbers = None):
    for gadget in self.gadgets[self.gadget_type_name(gadget_type)]:
      if no_clobbers == None or not gadget.clobbers_registers(no_clobbers):
        yield gadget

  def foreach_type_output(self, gadget_type, output, no_clobbers = None):
    for gadget in self.gadgets_per_output[self.gadget_type_name(gadget_type)][output]:
      if no_clobbers == None or not gadget.clobbers_registers(no_clobbers):
        yield gadget

  def find_gadget(self, gadget_type, input_registers = None, output_registers = None, no_clobber = None):
    """This method will find the best gadget (lowest complexity) given the search criteria"""
    best = best_complexity = None
    for gadget in self.foreach_type(gadget_type):
      if ((input_registers == None # Not looking for a gadget with a specific register as input
          or (gadget.inputs[0] == input_registers[0] # Only looking for one specific input
            and (len(gadget.inputs) == 1 or gadget.inputs[1] == input_registers[1]))) # Also looking to match the second input
        and (output_registers == None or gadget.outputs == output_registers) # looking to match the output
        and (no_clobber == None or not gadget.clobbers_registers(no_clobber)) # Can't clobber anything we need
        and (best == None or best_complexity > gadget.complexity())): # and it's got a better complexity than the current one
          best = gadget
          best_complexity = best.complexity()

    if best == None:
      return self.create_new_gadgets(gadget_type, input_registers, output_registers, no_clobber)
    return best

  def find_load_stack_gadget(self, register, no_clobber = None):
    """This method finds the best gadget (lowest complexity) to load a register from the stack"""
    if type(self.arch) == type(None):
      return None
    return self.find_gadget(LoadMem, [self.arch.registers['sp'][0]], [register], no_clobber)

  def find_load_const_gadget(self, register, value, no_clobber = None):
    """This method finds the best gadget (lowest complexity) to load a register from the stack"""
    for gadget in self.foreach_type_output(LoadConst, register, no_clobber):
      if gadget.params[0] == value:
        return gadget
    return None

  def find_load_register_gadgets(self, registers):
    gadgets = []

    for gadget in self.foreach_type_output(LoadMultiple):
      pass

    return gadgets

###########################################################################################################
## Synthesizing Gadgets ###################################################################################
###########################################################################################################

  def create_new_gadgets(self, gadget_type, inputs, outputs, no_clobbers):
    if hasattr(self, self.gadget_type_name(gadget_type)):
      return getattr(self, self.gadget_type_name(gadget_type))(inputs, outputs, no_clobbers)
    return None

  def LoadMem(self, inputs, outputs, no_clobbers):
    gadget = self.LoadMemFromMoveReg(inputs, outputs[0], no_clobbers)
    if gadget == None:
      gadget = self.LoadMemFromLoadMemJump(inputs, outputs[0], no_clobbers)
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

  def complexity(self):
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

  def __init__(self, arch, address, inputs, outputs, params, clobber, stack_offset, ip_in_stack_offset):
    self.arch = arch
    self.address = address
    self.inputs = inputs
    self.outputs = outputs
    self.params = params
    self.clobber = clobber
    self.stack_offset = stack_offset
    self.ip_in_stack_offset = ip_in_stack_offset

  def __str__(self):
    outputs = ", ".join([self.arch.translate_register_name(x) for x in self.outputs])
    if self.outputs != "":
      outputs = ", Output: {}".format(outputs)
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
      self.address, round(self.complexity(), 2), self.stack_offset, ip, outputs, inputs, clobber, params)

  def _is_stack_reg(self, reg):
    return reg == self.arch.registers['sp'][0]

  def clobbers_register(self, reg):
    """Check if the gadget clobbers the specified register"""
    for clobber in self.clobber:
      if clobber == reg:
        return True
    return (reg in self.outputs) or (reg in self.clobber)

  def clobbers_registers(self, regs):
    """Check if the gadget clobbers any of the specified registers"""
    for reg in regs:
      if self.clobbers_register(reg):
        return True
    return False

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

  def chain(self, next_address, input_value = None):
    """Default ROP Chain generation, uses no parameters"""
    chain = self.ip_in_stack_offset * "I"
    chain += utils.ap(next_address, self.arch)
    chain += (self.stack_offset - len(chain)) * "J"
    return chain

  def get_constraint(self):
    constraint, antialias_constraint = self.get_gadget_constraint()
    ip_stack_constraint = self.get_stack_ip_constraints()
    constraint = z3.Or(constraint, ip_stack_constraint)
    if antialias_constraint != None:
      constraint = z3.And(constraint, antialias_constraint)
    return constraint

  def get_gadget_constraint(self):
    raise RuntimeError("Not Implemented")

  def get_stack_ip_constraints(self):
    sp_before = self.get_reg_before(self.arch.registers['sp'][0])
    sp_after = self.get_reg_after(self.arch.registers['sp'][0])
    constraint = z3.Not(sp_after == sp_before + self.stack_offset)

    if self.ip_in_stack_offset != None:
      new_ip_value = utils.z3_get_memory(self.get_mem_before(), sp_before + self.ip_in_stack_offset, self.arch.bits, self.arch)
      ip_after = self.get_reg_after(self.arch.registers['ip'][0])
      if self.arch.name in extra_archinfo.ALIGNED_ARCHS: # For some architectures, pyvex adds a constraint to ensure new IPs are aligned
        new_ip_value = new_ip_value & ((2 ** self.arch.bits) - self.arch.instruction_alignment) # in order to properly validate, we must match that
      constraint = z3.Or(constraint, z3.Not(ip_after == new_ip_value))
    return constraint

  # Some z3 helper methods
  def get_reg_before(self, reg): return z3.BitVec("{}_before".format(self.arch.translate_register_name(reg)), self.arch.bits)
  def get_reg_after(self, reg):  return z3.BitVec("{}_after".format(self.arch.translate_register_name(reg)), self.arch.bits)
  def get_output(self, idx):     return self.get_reg_after(self.outputs[idx])
  def get_output0(self):         return self.get_output(0)
  def get_input(self, idx):      return self.get_reg_before(self.inputs[idx])
  def get_input0(self):          return self.get_input(0)
  def get_input1(self):          return self.get_input(1)
  def get_param(self, idx):      return z3.BitVecVal(self.params[idx], self.arch.bits)
  def get_param0(self):          return self.get_param(0)
  def get_mem(self, name):       return z3.Array("mem_{}".format(name), z3.BitVecSort(self.arch.bits), z3.BitVecSort(8))
  def get_mem_before(self):      return self.get_mem("before")
  def get_mem_after(self):       return self.get_mem("after")

  def get_antialias_constraint(self, address, register = "sp"):
    register = self.get_reg_before(self.arch.registers[register][0])
    num_bytes = self.arch.bits/8
    return z3.And(
      # Don't allow the address to be overlaping the register
      z3.Or(
        z3.ULT(address, register - num_bytes),
        z3.UGT(address, register + num_bytes)
      ),

      # Don't allow the address or register to wrap around
      z3.ULT(address, address + num_bytes),
      z3.UGT(address, address - num_bytes),
      z3.ULT(register, register + num_bytes),
      z3.UGT(register, register - num_bytes),
    )

###########################################################################################################
## The various Gadget types ###############################################################################
###########################################################################################################

class Jump(Gadget):
  def chain(self, next_address = None, input_value = None):
    return self.stack_offset * "H" # No parameters or IP in stack, just fill the stack offset

  def get_gadget_constraint(self):
    return z3.Not(self.get_output0() == self.get_input0()), None

class MoveReg(Gadget):
  def get_gadget_constraint(self):
    return z3.Not(self.get_output0() == self.get_input0()), None

class LoadConst(Gadget):
  def get_gadget_constraint(self):
    return z3.Not(self.get_output0() == self.get_param0()), None

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

  def get_gadget_constraint(self):
    mem_value = utils.z3_get_memory(self.get_mem_before(), self.get_input0() + self.get_param0(), self.arch.bits, self.arch)
    return z3.Not(self.get_output0() == mem_value), None

class LoadMemJump(LoadMem):
  """This gadget loads memory then jumps to a register (Used often in ARM)"""
  def get_gadget_constraint(self):
    load_constraint, antialias_constraint = super(LoadMemJump, self).get_gadget_constraint()
    jump_constraint = z3.Not(self.get_reg_after(self.arch.registers['ip'][0]) == self.get_input1())
    return z3.Or(load_constraint, jump_constraint), antialias_constraint

class LoadMultiple(LoadMem):
  """This gadget loads multiple registers at once"""
  def get_gadget_constraint(self):
    load_mem_constraint = None
    for i in range(len(self.outputs)):
      mem_value = utils.z3_get_memory(self.get_mem_before(), self.get_input0() + self.get_param(i), self.arch.bits, self.arch)
      new_constraint = z3.Not(self.get_output(i) == mem_value)
      if load_mem_constraint == None:
        load_mem_constraint = new_constraint
      else:
        load_mem_constraint = z3.Or(load_mem_constraint, new_constraint)
    return load_mem_constraint, None

class StoreMem(Gadget):
  def get_gadget_constraint(self):
    address = self.get_input0() + self.get_param0()
    mem_value = utils.z3_get_memory(self.get_mem_after(), address, self.arch.bits, self.arch)

    store_constraint = z3.Not(mem_value == self.get_input1())
    antialias_constraint = self.get_antialias_constraint(address)
    return store_constraint, antialias_constraint

class Arithmetic(Gadget):
  def get_gadget_constraint(self):
    return z3.Not(self.get_output0() == self.binop(self.get_input0(), self.get_input1())), None

class ArithmeticLoad(Gadget):
  def get_gadget_constraint(self):
    mem_value = utils.z3_get_memory(self.get_mem_before(), self.get_input0() + self.get_param0(), self.arch.bits, self.arch)
    return z3.Not(self.get_output0() == self.binop(mem_value, self.get_input1())), None

class ArithmeticStore(Gadget):
  def get_gadget_constraint(self):
    address = self.get_input0() + self.get_param0()
    in_mem_value = utils.z3_get_memory(self.get_mem_before(), address, self.arch.bits, self.arch)
    out_mem_value = utils.z3_get_memory(self.get_mem_after(), address, self.arch.bits, self.arch)

    store_constraint = z3.Not(out_mem_value == self.binop(in_mem_value, self.get_input1()))
    antialias_constraint = self.get_antialias_constraint(address)
    return store_constraint, antialias_constraint

# Split up the Arithmetic gadgets, so they're easy to search for when you are searching for a specific one
class AddGadget(Arithmetic):
  @classmethod
  def binop(self,x,y): return x + y

class SubGadget(Arithmetic):
  @classmethod
  def binop(self,x,y): return x - y

class MulGadget(Arithmetic):
  @classmethod
  def binop(self,x,y): return x * y

class AndGadget(Arithmetic):
  @classmethod
  def binop(self,x,y): return x & y

class OrGadget(Arithmetic):
  @classmethod
  def binop(self,x,y): return x | y

class XorGadget(Arithmetic):
  @classmethod
  def binop(self,x,y): return x ^ y


# Split up the Arithmetic Load gadgets, so they're easy to search for when you are searching for a specific one
class LoadAddGadget(ArithmeticLoad):
  @classmethod
  def binop(self,x,y): return x + y

class LoadSubGadget(ArithmeticLoad):
  @classmethod
  def binop(self,x,y): return x - y

class LoadMulGadget(ArithmeticLoad):
  @classmethod
  def binop(self,x,y): return x * y

class LoadAndGadget(ArithmeticLoad):
  @classmethod
  def binop(self,x,y): return x & y

class LoadOrGadget(ArithmeticLoad):
  @classmethod
  def binop(self,x,y): return x | y

class LoadXorGadget(ArithmeticLoad):
  @classmethod
  def binop(self,x,y): return x ^ y

# Split up the Arithmetic Store gadgets, so they're easy to search for when you are searching for a specific one
class StoreAddGadget(ArithmeticStore):
  @classmethod
  def binop(self,x,y): return x + y

class StoreSubGadget(ArithmeticStore):
  @classmethod
  def binop(self,x,y): return x - y

class StoreMulGadget(ArithmeticStore):
  @classmethod
  def binop(self,x,y): return x * y

class StoreAndGadget(ArithmeticStore):
  @classmethod
  def binop(self,x,y): return x & y

class StoreOrGadget(ArithmeticStore):
  @classmethod
  def binop(self,x,y): return x | y

class StoreXorGadget(ArithmeticStore):
  @classmethod
  def binop(self,x,y): return x ^ y
