
class Const(object):
  def __init__(self, value):
    self.value = value

  def __str__(self):
    return str(self.value)

class Register(object):
  def __init__(self, name):
    self.name = name

  def __str__(self):
    return self.name

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

