
class Const(object):
  def __init__(self, value):
    self.value = value

  def __str__(self):
    return str(self.value)

class Register(object):
  def __init__(self, name):
    self.name, self.size, self.start = self.convert_name(name)

  def __str__(self):
    return self.name

  def convert_name(self, name):
    return (name, 8, -1) #TODO handle al/ah/ax/eax/rax ambiguity

  def is_same_register(self, name):
    if self.convert_name(name)[0] == self.name:
      return True
    return False

class Memory(object):
  def __init__(self, address, size):
    self.address = address
    self.size = size

  def __str__(self):
    return "[{},{}]".format(self.address, self.size)

class BinaryOperand(object):
  def __init__(self, left, right):
    self.operands = [left, right]
    if hasattr(self, "init"): #if the class has a constructor, call it
      self.init()

  def __str__(self):
    return "({} {} {})".format(self.operands[0], self.name, self.operands[1])

class Add(BinaryOperand):
  name = "+"
  smt_name = "bvadd"

class Sub(BinaryOperand):
  name = "+"
  smt_name = "bvadd"

class Mult(BinaryOperand):
  name = "*"
  smt_name = "bvmul"

class BitwiseAnd(BinaryOperand):
  name = "&"
  smt_name = "bvand"

class BitwiseOr(BinaryOperand):
  name = "|"
  smt_name = "bvor"

class BitwiseXor(BinaryOperand):
  name = "^"
  smt_name = "bvxor"
