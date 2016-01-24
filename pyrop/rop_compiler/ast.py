# This file holds the Abstract Syntax Tree classes for expressions built when emulating the gadget's instructions.  Note that
# it is not complete and limited to just the operations that are useful in ROP gadgets.
import z3

class BaseType(object):
  """A base class that all of the operand types (Const, Register, Memory) derive from."""

  def is_rip_or_rsp(self):
    """A convience method to quickly determine if this object represents the special rip or rsp Registers"""
    return type(self) == Register and (self.name == "rip" or self.name == "rsp")

class Const(BaseType):
  """This class holds a immediate operand from instructions."""
  def __init__(self, value):
    self.value = value

  def __str__(self):
    return str(self.value)

  def to_z3(self):
    return self.value

  def compute(self, input_registers, memory):
    return self.value

class Register(BaseType):
  def __init__(self, offset):
    self.offset = offset

  def __str__(self):
    return self.name

class Memory(BaseType):
  """This class holds a memory operand from any instructions.  The address property holds the address of the memory operand and
    can be any of the other operand types."""
  def __init__(self, address, size = 8):
    self.address = address
    self.size = size

  def __str__(self):
    return "Mem[{}]".format(self.address)

  def __repr__(self):
    return "(select Memory %s)" % repr(self.address)

  def store_smt2(self, value):
    return "(store Memory {})".format(repr(value))

  def to_z3(self):
    return z3.Array("Memory", z3.BitVecSort(64), z3.BitVecSort(64))[self.address.to_z3()]

  def is_same_memory(self, other):
    # TODO convert this to use the solver to determine this so it can allow more types

    address1, address2 = self.address, other.address
    if type(address1) != type(address2):
      return False

    if ((type(address1) == Const and address1.value == address2.value) or
        (type(address1) == Register and address1.name == address2.name)):
      return True # References the same address or

    if not issubclass(address1.__class__, BinaryOp):
      return False # We're not going to go too deep with this, so really only consider the type [reg] or [reg operand const]

    reg1 = const1 = reg2 = const2 = None
    for operand in address1.operands:
      if type(operand) == Register:
        reg1 = operand
      elif type(operand) == Const:
        con1 = operand
    for operand in address2.operands:
      if type(operand) == Register:
        reg2 = operand
      elif type(operand) == Const:
        con2 = operand

    if None in [reg1, reg2] or type(const1) != type(const2):
      return False

    return reg1.name == reg2.name and (None in [const1, const2] or const1.value == const2.value)

  def compute(self, input_registers, memory):
    return memory[self.address.compute(input_registers, memory)] # Don't evaluate the memory

class Operation(object):
  """The base class for instruction operations (add, subtract, etc) in the AST."""
  def __init__(self):
    self.operands = []

class UnaryOp(Operation):
  """Parent class for any operation types that take 1 operands."""
  def __init__(self, operand):
    super(UnaryOp, self).__init__()
    self.operands = [operand]

  def __str__(self):
    return "({}({}))".format(self.name, self.operands[0])

class Un64to32(UnaryOp):
  name = "64to32"

class BinaryOp(Operation):
  """Parent class for any operation types that take 2 operands."""
  def __init__(self, left, right):
    super(BinaryOp, self).__init__()
    self.operands = [left, right]

  def __str__(self):
    return "({} {} {})".format(self.operands[0], self.name, self.operands[1])

  def to_z3(self):
    first = self.operands[0].to_z3()
    return self.operand(self.operands[0].to_z3(), self.operands[1].to_z3())

  def compute(self, input_registers, memory):
    return self.operand(self.operands[0].compute(input_registers, memory), self.operands[1].compute(input_registers, memory))

class Add(BinaryOp):
  name = "+"
  operand = (lambda self,x,y: x + y)

class Sub(BinaryOp):
  name = "-"
  operand = (lambda self,x,y: x - y)

class Mult(BinaryOp):
  name = "*"
  operand = (lambda self,x,y: x * y)

class BitwiseAnd(BinaryOp):
  name = "&"
  operand = (lambda self,x,y: x & y)

class BitwiseOr(BinaryOp):
  name = "|"
  operand = (lambda self,x,y: x | y)

class BitwiseXor(BinaryOp):
  name = "^"
  operand = (lambda self,x,y: x ^ y)

class Equal(BinaryOp):
  name = "="
  operand = (lambda self,x,y: x == y)

class Store(BinaryOp):
  name = "Memory"


if __name__ == "__main__":
  inputs = { "rbx" : 9 }
  add8 = Add(Register("rbx"), Const(8))
  print add8, "=", add8.compute({"rbx" : 9}, {}),"for inputs:",inputs

  s = z3.Solver()
  equation = Equal(Add(Register("rbx"), Const(8)), Const(10))
  s.add(equation.to_z3())
  if s.check() == z3.sat:
    print "Equation:", equation, "Model:", s.model()

  z3.solve(Equal(Add(Memory(Const(0x1234)), Const(8)), Const(10)).to_z3())

