import math

class Gadget(object):
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
    return "{}(Address: 0x{:x}, Complexity {}, Stack Offset 0x{:x}{}{}{}{})".format(self.__class__.__name__, self.address,
      self.complexity(), self.stack_offset, output, inputs, clobber, params)

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
    elif self.stack_offset - 8 != self.ip_in_stack_offset:
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

# The various Gadget types
class Jump(Gadget):            pass
class MoveReg(Gadget):         pass
class LoadConst(Gadget):       pass
class LoadMem(Gadget):         pass
class Arithmetic(Gadget):      pass
class StoreMem(Gadget):        pass
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
