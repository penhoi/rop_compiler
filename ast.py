import z3

class Const(object):
  def __init__(self, value):
    self.value = value

  def __str__(self):
    return str(self.value)

  def to_z3(self):
    return self.value

class Register(object):
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
    return self.name + str(self.handle)

  def to_z3(self):
    return z3.BitVec(str(self), self.size * 8)

  def convert_name(self, name):
    return (name, 8, -1) #TODO handle al/ah/ax/eax/rax ambiguity

  def is_same_register(self, name):
    if self.convert_name(name)[0] == self.name:
      return True
    return False

class Memory(object):
  def __init__(self, address, size = 8):
    self.address = address
    self.size = size

  def __str__(self):
    return "[{},{}]".format(self.address, self.size)

  def __repr__(self):
    return "(select Memory %s)" % repr(self.address)

  def store_smt2(self, value):
    return "(store Memory {})".format(repr(value))

  def to_z3(self):
    return z3.Array("Memory", z3.BitVecSort(64), z3.BitVecSort(64))[self.address.to_z3()]

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
    return getattr(first, self.z3_name)(self.operands[1].to_z3())
    return self.operand(self.operands[0].to_z3(), self.operands[1].to_z3())

class Add(BinaryOperand):
  name = "+"
  z3_name = "__add__"

class Sub(BinaryOperand):
  name = "-"
  z3_name = "__sub__"

class Mult(BinaryOperand):
  name = "*"
  z3_name = "__mul__"

class BitwiseAnd(BinaryOperand):
  name = "&"
  z3_name = "__and__"

class BitwiseOr(BinaryOperand):
  name = "|"
  z3_name = "__or__"

class BitwiseXor(BinaryOperand):
  name = "^"
  z3_name = "__xor__"

class Equal(BinaryOperand):
  name = "="
  z3_name = "__eq__"

class Store(BinaryOperand):
  name = "Memory"
  z3_name = "store Memory"


if __name__ == "__main__":
  s = z3.Solver()
  s.add(Equal(Add(Register("rbx"), Const(8)), Const(10)).to_z3())
  if s.check() == z3.sat:
    print "Model:",s.model()

  z3.solve(Equal(Add(Memory(Const(0x1234)), Const(8)), Const(10)).to_z3())

