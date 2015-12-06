import z3

class BaseType(object):
  def is_rip_or_rsp(self):
    return type(self) == Register and (self.name == "rip" or self.name == "rsp")

class Const(BaseType):
  def __init__(self, value):
    self.value = value

  def __str__(self):
    return str(self.value)

  def to_z3(self):
    return self.value

  def compute(self, input_registers, memory):
    return self.value

class Register(BaseType):
  MAX_HANDLE = 0

  @classmethod
  def new_handle(cls):
    handle = cls.MAX_HANDLE
    cls.MAX_HANDLE += 1
    return handle

  def __init__(self, name, handle = None):
    self.name, self.size, self.start = self.convert_name(name)
    self.handle = handle
    if self.handle == None:
      self.handle = Register.new_handle()

  def __str__(self):
    return self.name

  def to_z3(self):
    return z3.BitVec(str(self), self.size * 8)

  def convert_name(self, name):
    return (name, 8, -1) #TODO handle al/ah/ax/eax/rax ambiguity

  def is_same_register(self, name):
    if ((type(name) == str and self.convert_name(name)[0] == self.name)
        or (type(name) == Register and name.name == self.name)):
      return True
    return False

  def compute(self, input_registers, memory):
    return input_registers[self.name]

class Memory(BaseType):
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

    if not issubclass(address1.__class__, BinaryOperand):
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

class Operand(object):
  def __init__(self):
    self.operands = []

class BinaryOperand(Operand):
  def __init__(self, left, right):
    super(BinaryOperand, self).__init__()
    self.operands = [left, right]
    if hasattr(self, "init"): #if the class has a constructor, call it
      self.init()

  def __str__(self):
    return "({} {} {})".format(self.operands[0], self.name, self.operands[1])

  def to_z3(self):
    first = self.operands[0].to_z3()
    #return getattr(first, self.z3_name)(self.operands[1].to_z3())
    return self.operand(self.operands[0].to_z3(), self.operands[1].to_z3())

  def compute(self, input_registers, memory):
    return self.operand(self.operands[0].compute(input_registers, memory), self.operands[1].compute(input_registers, memory))

class Add(BinaryOperand):
  name = "+"
  z3_name = "__add__"
  operand = (lambda self,x,y: x + y)

class Sub(BinaryOperand):
  name = "-"
  z3_name = "__sub__"
  operand = (lambda self,x,y: x - y)

class Mult(BinaryOperand):
  name = "*"
  z3_name = "__mul__"
  operand = (lambda self,x,y: x * y)

class BitwiseAnd(BinaryOperand):
  name = "&"
  z3_name = "__and__"
  operand = (lambda self,x,y: x & y)

class BitwiseOr(BinaryOperand):
  name = "|"
  z3_name = "__or__"
  operand = (lambda self,x,y: x | y)

class BitwiseXor(BinaryOperand):
  name = "^"
  z3_name = "__xor__"
  operand = (lambda self,x,y: x ^ y)

class Equal(BinaryOperand):
  name = "="
  z3_name = "__eq__"
  operand = (lambda self,x,y: x == y)

class Store(BinaryOperand):
  name = "Memory"
  z3_name = "store Memory"


if __name__ == "__main__":
  inputs = { "rbx" : 9 }
  add8 = Add(Register("rbx"), Const(8))
  print add8, "=", add8.compute({"rbx" : 9}, {}),"for inputs:",inputs

  s = z3.Solver()
  s.add(Equal(Add(Register("rbx"), Const(8)), Const(10)).to_z3())
  if s.check() == z3.sat:
    print "Model:",s.model()

  z3.solve(Equal(Add(Memory(Const(0x1234)), Const(8)), Const(10)).to_z3())


