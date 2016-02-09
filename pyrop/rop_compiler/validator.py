import collections
import z3
import gadget

class Validator(object):

  def __init__(self):
    pass

  def validate_gadget(self, gadget, irsb):
    pass

class PyvexToZ3Converter(object):

  def __init__(self, arch):
    self.arch = arch
    self.stmt = []
    self.name_count = collections.defaultdict(int, {})
    self.memory = z3.Array(self.get_name("mem", True), z3.BitVecSort(self.arch.bits), z3.BitVecSort(8))

  def get_smt_statements(self, irsb):
    self.stmt = []
    for stmt in irsb.statements:
      #try:
        if hasattr(self, stmt.tag):
          getattr(self, stmt.tag)(stmt)
        else:
          return None
      #except:
      #  return None
    return self.stmt

  # Statement Generators

  def append_assignment(self, left, right):
    self.stmt.append(left == right)

  def get_tmp(self, tmp, size):
    return z3.BitVec('tmp{}'.format(tmp), size)

  def set_tmp(self, tmp, value):
    return self.append_assignment(tmp, value)

  def get_name(self, name, is_reg = True):
    if is_reg:
      name = self.arch.translate_register_name(name)
    unique_name = "{}_{}".format(name, self.name_count[name])
    self.name_count[name] += 1
    return unique_name

  def get_reg(self, reg, size):
    return z3.BitVec(self.get_name(reg), size)

  def set_reg(self, reg, size, value):
    reg = z3.BitVec(self.get_name(reg), size)
    return self.append_assignment(reg, value)

  def set_mem(self, address, value):
    new_memory = z3.Array(self.get_name("mem", True), z3.BitVecSort(self.arch.bits), z3.BitVecSort(8))
    self.append_assignment(new_memory, z3.Store(self.memory, address, value))
    self.memory = new_memory

  def get_mem(self, address, size):
    value = z3.Select(self.memory, address)
    for i in range(1, size/8): 
      new_byte = z3.Select(self.memory, address + (i*8))
      if self.arch.memory_endness == 'Iend_LE':
        value = z3.Concat(new_byte, value)
      else:
        value = z3.Concat(value, new_byte)
    return value

  def Ist_WrTmp(self, stmt):
    value = getattr(self, stmt.data.tag)(stmt.data)
    tmp = self.get_tmp(stmt.tmp, stmt.data.result_size)
    self.set_tmp(tmp, value)

  def Ist_Put(self, stmt):
    value = getattr(self, stmt.data.tag)(stmt.data)
    size = stmt.data.result_size
    self.set_reg(stmt.offset, size, value)

  def Ist_Store(self, stmt):
    address = getattr(self, stmt.addr.tag)(stmt.addr)
    value = getattr(self, stmt.data.tag)(stmt.data)
    self.set_mem(address, value)

  def Ist_IMark(self, stmt): pass
  def Ist_NoOp(self, stmt):  pass
  def Ist_AbiHint(self, stmt): pass
  def Ist_Exit(self, stmt): pass

  # Expression Emulators

  def Iex_Get(self, expr):
    return self.get_reg(expr.offset, expr.result_size)
    
  def Iex_RdTmp(self, argument):
    return self.get_tmp(argument.tmp, argument.result_size)

  def Iex_Load(self, expr):
    address = getattr(self, expr.addr.tag)(expr.addr)
    return self.get_mem(address, expr.result_size)
    
  def Iex_Const(self, expr):
    return getattr(self, expr.con.tag)(expr.con)

  def Ico_U8(self, constant):
    return z3.BitVecVal(constant.value, 8)

  def Ico_U32(self, constant):
    return z3.BitVecVal(constant.value, 32)

  def Ico_U64(self, constant):
    return z3.BitVecVal(constant.value, 64)

  def Iex_Unop(self, expr):
    argument = getattr(self, expr.args[0].tag)(expr.args[0])
    return getattr(self, expr.op)(argument)

  def Iop_64to32(self, argument):
    return z3.Extract(31, 0, argument)

  def Iop_64to8(self, argument):
    return z3.Extract(7, 0, argument)

  def Iop_32Uto64(self, argument):
    return z3.ZeroExt(32, argument)

  def Iop_8Uto64(self, argument):
    return z3.ZeroExt(56, argument)

  def Iop_8Sto64(self, argument):
    return z3.SignExt(56, argument)

  def Iop_32Sto64(self, argument):
    return z3.SignExt(32, argument)

  def Iex_Binop(self, expr):
    left = getattr(self, expr.args[0].tag)(expr.args[0])
    right = getattr(self, expr.args[1].tag)(expr.args[1])
    return getattr(self, expr.op)(left, right)

  def Iop_And64(self, left, right): return left & right
  def Iop_And32(self, left, right): return left & right

  def Iop_Xor64(self, left, right): return left ^ right
  def Iop_Xor32(self, left, right): return left ^ right

  def Iop_Add64(self, left, right): return left + right
  def Iop_Add32(self, left, right): return left + right
  def Iop_Add8(self, left, right):  return left + right

  def Iop_Sub64(self, left, right): return left - right
  def Iop_Sub32(self, left, right): return left - right

  def Iop_Shl64(self, left, right): return left << right
  def Iop_Shl32(self, left, right): return left << right

  def Iop_CmpEQ64(self, left, right): return left == right
  def Iop_CmpEQ32(self, left, right): return left == right

  def Iop_CmpNE64(self, left, right): return left != right
  def Iop_CmpNE32(self, left, right): return left != right

if __name__ == "__main__":
  import pyvex, archinfo
  arch = archinfo.ArchAMD64()
  converter = PyvexToZ3Converter(arch)

  code = '\x5f\xc3'
  irsb = pyvex.IRSB(code, 0x40000, arch)
  irsb.pp()
  print converter.get_smt_statements(irsb)

