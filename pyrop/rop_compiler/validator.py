import collections
import z3
import gadget, utils, extra_archinfo

class Validator(object):

  def __init__(self, arch):
    self.arch = arch

  def validate_gadget(self, gadget, irsbs):
    converter = PyvexToZ3Converter(self.arch)
    solver = z3.Solver()
    for i in range(len(irsbs)):
      statements = converter.get_smt_statements(irsbs[i], i)
      if statements == None:
        return False
      for statement in statements:
        solver.append(statement)
    solver.append(gadget.get_constraint())
    result = solver.check()
    return result == z3.unsat

class PyvexToZ3Converter(object):

  def __init__(self, arch):
    self.arch = arch
    self.stmt = []
    self.out_regs = {}
    self.reg_count = collections.defaultdict(int, {})

    # Make sure all the registers have initial BitVecs in the constraints
    for name, (num, size) in self.arch.registers.items():
      real_name = self.arch.translate_register_name(num) # So we don't get both sp and rsp, ip and rip, etc.
      if real_name not in self.out_regs and real_name not in extra_archinfo.IGNORED_REGISTERS[self.arch.name]:
        self.out_regs[num] = z3.BitVec("{}_before".format(real_name), size * 8)

    # Setup the initial memory
    self.memory = z3.Array("mem_before", z3.BitVecSort(self.arch.bits), z3.BitVecSort(8))
    self.mem_count = 0
    self.first_mem = self.memory

  def get_smt_statements(self, irsb, irsb_num):
    self.irsb_num = irsb_num
    for stmt in irsb.statements:
      if hasattr(self, stmt.tag):
        getattr(self, stmt.tag)(stmt)
      else:
        return None

    # Make some _after variables so it's easy to get their value
    for name, reg in self.out_regs.items():
      self.append_assignment(reg, z3.BitVec('{}_after'.format(self.arch.translate_register_name(name)), reg.size()))
    self.append_assignment(self.memory, z3.Array("mem_after", z3.BitVecSort(self.arch.bits), z3.BitVecSort(8)))

    return self.stmt

  # Statement Generators

  def append_assignment(self, left, right):
    self.stmt.append(left == right)

  def get_tmp(self, tmp, size):
    name = 'tmp{}_{}'.format(self.irsb_num, tmp)
    if size == None:
      return z3.Bool(name)
    return z3.BitVec(name, size)

  def set_tmp(self, tmp, value):
    return self.append_assignment(tmp, value)

  def get_reg(self, reg, size):
    if reg in self.out_regs:
      return self.out_regs[reg]
    return z3.BitVec("{}_before".format(self.arch.translate_register_name(reg)), size)

  def set_reg(self, reg_num, size, value):
    unique_name = "{}_{}".format(self.arch.translate_register_name(reg_num), self.reg_count[reg_num])
    self.reg_count[reg_num] += 1

    reg = z3.BitVec(unique_name, size)
    self.out_regs[reg_num] = reg
    self.append_assignment(reg, value)

  def set_mem(self, address, value):
    unique_name = "mem_{}".format(self.mem_count)
    new_memory = z3.Array(unique_name, z3.BitVecSort(self.arch.bits), z3.BitVecSort(8))
    self.mem_count += 1

    self.memory = utils.z3_set_memory(self.memory, address, value, self.arch)
    self.append_assignment(new_memory, self.memory)
    self.memory = new_memory

  def get_mem(self, address, size):
    return utils.z3_get_memory(self.memory, address, size, self.arch)

  def Ist_WrTmp(self, stmt):
    value = getattr(self, stmt.data.tag)(stmt.data)
    if value.__class__ == z3.BoolRef: # Check to see if the tmp should be a bool, pyvex doesn't
      tmp = self.get_tmp(stmt.tmp, None) # differentiate between a BitVec of size 1 and a Bool
    else:
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

  def Iop_1Sto32(self, argument):
    return z3.SignExt(31, argument)

  def Iop_1Sto64(self, argument):
    return z3.SignExt(63, argument)

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

  def Iop_Or64(self, left, right):  return left | right
  def Iop_Or32(self, left, right):  return left | right

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

