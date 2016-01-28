import math, struct

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

  def ap(self, address):
    """Packs an address into a string. ap is short for Address Pack"""
    formats = { 32 : "I", 64 : "Q" }
    if type(address) == str: # Assume already packed
      return address
    if address < 0:
      address = (2 ** self.arch.bits) + address
    return struct.pack(formats[self.arch.bits], address)

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
    chain = ""
    for i in range(len(self.gadgets)):
      next_gadget_address = next_address
      if i + 1 < len(self.gadgets):
        next_gadget_address = self.gadgets[i+1].address
      chain += self.gadgets[i].chain(next_gadget_address, input_value)
    return chain

class Gadget(GadgetBase):
  """This class wraps a set of instructions and holds the associated metadata that makes up a gadget"""

  def __init__(self, arch, irsb, inputs, output, params, clobber, stack_offset, ip_in_stack_offset):
    self.arch = arch
    self.irsb = irsb
    self.address = irsb._addr
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
      self.address, self.complexity(), self.stack_offset, ip, output, inputs, clobber, params)

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
    return self.clobbers_register(name) or (type(self.output) == Register and self.output.name == name)

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
    chain += self.ap(next_address)
    chain += (self.stack_offset - len(chain)) * "J"
    return chain

# The various Gadget types
class Jump(Gadget):
  def chain(self, next_address = None, input_value = None): 
    return self.stack_offset * "H" # No parameters or IP in stack, just fill the stack offset

class MoveReg(Gadget):         pass
class LoadConst(Gadget):       pass

class LoadMem(Gadget):
  def chain(self, next_address, input_value = None): 
    chain = ""

    # If our input value is supposed to come before the next PC address, add it to the chain now
    if input_value != None and self.params[0] < self.ip_in_stack_offset:
      chain += self.params[0] * "A"
      chain += self.ap(input_value)

    chain += (self.ip_in_stack_offset - len(chain)) * "B"
    chain += self.ap(next_address)

    # If our input value is supposed to come after the next PC address, add it to the chain now
    if input_value != None and self.params[0] > self.ip_in_stack_offset:
      chain += (self.params[0] - len(chain)) * "A"
      chain += self.ap(input_value)

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
