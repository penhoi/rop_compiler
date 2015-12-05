from capstone.x86 import *
import collections, logging

from ast import *
import enum

class Gadget(object):

  def __init__(self, insts, inputs, output, effects):
    self.insts = insts
    self.address = insts[0].address
    self.inputs = inputs
    self.output = output
    self.effects = effects

    self.clobber = []
    for (dst, value) in self.effects:
      if dst != self.output and not dst.is_rip_or_rsp():
        self.clobber.append(dst)

  def __str__(self):
    insts = "; ".join(["{} {}".format(inst.mnemonic, inst.op_str) for inst in self.insts])
    effects = "; ".join(["{} = {}".format(dst, value) for (dst, value) in self.effects])
    return "{}(0x{:x}):\nInsts: {}\nEffects: {}\nOutput: {} Input(s): ({}) Clobbers ({})".format(self.__class__.__name__,
      self.address, insts, effects, self.output, ", ".join([str(x) for x in self.inputs]),
      ", ".join([str(x) for x in self.clobber]))

  def clobbers_register(self, name):
    for clobber in self.clobber:
      if type(clobber) == Register and clobber.name == name:
        return True
    return False

  def uses_register(self, name):
    for an_input in self.inputs:
      if type(an_input) == Register and an_input.name == name:
        return True
    return self.clobbers_register(name) or (type(self.output) == Register and self.output.name == name)

  def complexity(self):
    return len(self.clobber)

  def to_statements(self):
    statements = []
    for (dst,value) in self.effects:
      if type(dst) == Register:
        statements.append(Equal(Register(dst.name, "_output"), value))
      else: 
        statements.append(Store(dst.address, value))
    return statements

  def output_register_names(self):
    names = []
    for (dst, value) in self.effects:
      if type(dst) == Register:
        names.append(dst.name)
    return names

class GadgetClassifier(object):

  def __init__(self, log_level = logging.WARNING):
    logging.basicConfig(format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    self.logger = logging.getLogger(self.__class__.__name__)
    self.logger.setLevel(log_level)

    self.instruction_emulators = collections.defaultdict((lambda: self.unknown_instruction), {
      "ret" : self.RET,
      "add" : self.ADD, "sub"  : self.SUB,
      "and" : self.AND, "or"   : self.OR,
      "xor" : self.XOR,
      "pop" : self.POP, "push" : self.PUSH,
      "mov" : self.MOV, "movabs" : self.MOV,
      "xchg" : self.XCHG,
      "nop" : self.NOP,
    })

  def create_gadget_from_instructions(self, insts):
    self.effects = []
    for inst in insts:
      try:
        self.instruction_emulators[inst.mnemonic](inst)
      except RuntimeError, err:
        self.logger.info(err)
        return None

    found = 0
    for (dst, value) in self.effects:
      if type(dst) == Register and (dst.is_same_register("rsp") or dst.is_same_register("rip")):
        found += 1
    if found != 2:
      return None # Make sure we have a way to change rsp and rip

    gadget_type, inputs, outputs = self.get_type_and_info()
    if gadget_type == GadgetTypes.MOV_REG:
      return MoveReg(insts, inputs, outputs, self.effects)
    elif gadget_type == GadgetTypes.LOAD_CONST:
      return LoadConst(insts, inputs, outputs, self.effects)
    elif gadget_type == GadgetTypes.ARITHMETIC:
      return Arithmetic(insts, inputs, outputs, self.effects)
    elif gadget_type == GadgetTypes.LOAD_MEM:
      return LoadMem(insts, inputs, outputs, self.effects)
    elif gadget_type == GadgetTypes.LOAD_STACK:
      return LoadStack(insts, inputs, outputs, self.effects)
    elif gadget_type == GadgetTypes.STORE_MEM:
      return StoreMem(insts, inputs, outputs, self.effects)
    elif gadget_type == GadgetTypes.ARITHMETIC_LOAD:
      return ArithmeticLoad(insts, inputs, outputs, self.effects)
    elif gadget_type == GadgetTypes.ARITHMETIC_STORE:
      return ArithmeticStore(insts, inputs, outputs, self.effects)
    return None

  def is_address_based_off_stack(self, address):
    registers = self.get_registers_in_address(address)

    # TODO consider cases where the address is something like [rsp+rax]
    if len(registers) == 1 and registers[0].name == "rsp":
      return True
    return False

  def get_leaf_nodes(self, value):
    if type(value) == Const or type(value) == Register:
      return [value]
    elif type(value) == int:
      return [Const(value)]
    elif type(value) == Memory:
      return self.get_leaf_nodes(value.address)
    elif issubclass(value.__class__, Operand):
      leafs = []
      for operand in value.operands:
        leafs.extend(self.get_leaf_nodes(operand))
      return leafs

    raise RuntimeError("Unknown type in get_leaf_nodes {}".format(type(value)))

  def get_registers_in_address(self, address):
    leafs = self.get_leaf_nodes(address)
    registers = []
    for leaf in leafs:
      if type(leaf) == Register:
        registers.append(leaf)
    return registers

  def is_simple_operand_type(self, operand):
    # TODO Expand this to allow for addressing by bigger binary operands (i.e. (rax + 8) * 32)
    return (
          (type(operand) == Register)
        or
          (issubclass(operand.__class__, Operand) and
          ((type(operand.operands[0]) == Register and type(operand.operands[1]) == Const) or
          (type(operand.operands[0]) == Const and type(operand.operands[1]) == Register)))
        )

  def is_simple_memory_value(self, memory):
    """ Gets whether a memory has a simple address, i.e. is the value memory[reg] or memory[reg operand const] (where operand
      is any binary operand)"""
    return (type(memory) == Memory and self.is_simple_operand_type(memory.address))

  def get_type_and_info(self):
    memory_writes = []
    register_writes = []
    for (dst, value) in self.effects:
      if type(dst) == Memory:
        memory_writes.append((dst,value))
      elif type(dst) == Register:
        if dst.name == "rsp" or dst.name == "rip": # ignore the ret part of the gadget
          continue
        register_writes.append((dst,value))

    if len(memory_writes) > 1: # A little heuristic, we don't want to deal with multiple memory writes
      return (GadgetTypes.UNKNOWN, [], None)

    for (dst, value) in register_writes:
      if type(value) == Register:
        return (GadgetTypes.MOV_REG, [value], dst)
      elif type(value) == Const:
        return (GadgetTypes.LOAD_CONST, [value], dst)
      elif type(value) == Memory:
        if self.is_address_based_off_stack(value.address):
          return (GadgetTypes.LOAD_STACK, [value], dst)
        elif self.is_simple_memory_value(value):
          return (GadgetTypes.LOAD_MEM, [value], dst)
      elif issubclass(value.__class__, Operand):
        if type(value.operands[0]) == Register and type(value.operands[1]) == Register:
          return (GadgetTypes.ARITHMETIC, [value.operands[0], value.operands[1]], dst)

        non_dst = None
        if dst.is_same_register(value.operands[0]):
          non_dst = value.operands[1]
        elif dst.is_same_register(value.operands[1]):
          non_dst = value.operands[0]

        if non_dst != None and self.is_simple_memory_value(non_dst):
          return (GadgetTypes.ARITHMETIC_LOAD, [value.operands[0], value.operands[1]], dst)

    for (dst, value) in memory_writes:
      if not self.is_simple_memory_value(dst):
        continue

      if type(value) == Register:
        return (GadgetTypes.STORE_MEM, [value, self.get_registers_in_address(dst)[0]], dst)
      elif issubclass(value.__class__, Operand):
        possible_dst = non_dst = None
        if (type(value.operands[0]) == Memory and type(value.operands[1]) == Register):
          possible_dst = value.operands[0]
        elif (type(value.operands[0]) == Register and type(value.operands[1]) == Memory):
          possible_dst = value.operands[1]

        if possible_dst != None and dst.is_same_memory(possible_dst):
          return (GadgetTypes.ARITHMETIC_STORE, [value.operands[0], value.operands[1]], dst)

    return (GadgetTypes.UNKNOWN, [], None)

############################################################################################
## Helper Utilities ########################################################################
############################################################################################

  def resolve_register(self, inst, reg_num):
    if reg_num == X86_REG_INVALID:
      return None
    name = inst.reg_name(reg_num)
    for (dst, value) in self.effects:
      if type(dst) == Register and dst.is_same_register(name):
        return value
    return Register(name, "_input")

  def rsp(self, inst): return self.resolve_register(inst, X86_REG_RSP)
  def rip(self, inst): return self.resolve_register(inst, X86_REG_RIP)

  def resolve_memory(self, inst, op):
    address = self.resolve_register(inst, op.mem.base)
    index = self.resolve_register(inst, op.mem.index)
    if index != None:
      if op.mem.scale != 1:
        index = Mult(index, Const(op.mem.scale))

      if address == None:
        address = index
      else:
        address = Add(address, index)

    if op.mem.disp != 0:
      const = Const(op.mem.disp)
      if address == None:
        address = const
      else:
        address = Add(address, const)
    return Memory(address, op.size)

  def get_operand_value(self, inst, op):
    if op.type == X86_OP_IMM:
      return Const(op.imm)
    elif op.type == X86_OP_REG:
      return self.resolve_register(inst, op.reg)
    elif op.type == X86_OP_MEM:
      return self.resolve_memory(inst, op)
    raise RuntimeError("Unknown operand type: {}".format(op.type))

  def get_operand_values(self, inst):
    return [self.get_operand_value(inst, op) for op in inst.operands]

  def set_operand_value(self, dst, new_value):
    remove_this = None
    for (destination, old_value) in self.effects:
      if type(destination) == Register and type(dst) == Register and destination.is_same_register(dst.name):
        remove_this = (destination, old_value)
      # TODO detect memory overwrites here
    if remove_this != None:
      self.effects.remove(remove_this)
    self.effects.append((dst, new_value))

  def set_register_value(self, name, value):
    self.set_operand_value(Register(name), value)

############################################################################################
## Instruction Emulators ###################################################################
############################################################################################

  def unknown_instruction(self, inst):
    raise RuntimeError("Unknown instruction: {}".format(inst.mnemonic))

  def binary(self, inst, operand):
    dst, src = self.get_operand_values(inst)
    self.set_operand_value(dst, operand(dst, src))

  def ADD(self, inst): self.binary(inst, Add)
  def SUB(self, inst): self.binary(inst, Sub)
  def AND(self, inst): self.binary(inst, BitwiseAnd)
  def  OR(self, inst): self.binary(inst, BitwiseOr)
  def XOR(self, inst): self.binary(inst, BitwiseXor)

  def POP(self, inst):
    dst = self.get_operand_values(inst)[0]
    rsp = self.rsp(inst)
    self.set_operand_value(dst, Memory(rsp, 8))
    self.set_register_value("rsp", Add(rsp, Const(8)))

  def PUSH(self, inst):
    src = self.get_operand_values(inst)
    rsp = self.rsp(inst)
    self.set_operand_value(Memory(rsp, 8), src)
    self.set_register_value("rsp", Sub(rsp, Const(8)))

  def RET(self, inst):
    rsp = self.rsp(inst)
    rip = self.rip(inst)

    amount = self.get_operand_values(inst)
    stack_diff = 8
    if len(amount) != 0:
      stack_diff += amount[0].value # will always be an immediate

    self.set_operand_value(rip, Memory(rsp, 8))
    self.set_register_value("rsp", Add(rsp, Const(stack_diff)))

  def MOV(self, inst):
    dst, src = self.get_operand_values(inst)
    self.set_operand_value(dst, src)

  def XCHG(self, inst):
    dst, src = self.get_operand_values(inst)
    self.set_operand_value(dst, src)
    self.set_operand_value(src, dst)

  def NOP(self, inst):
    pass

class MoveReg(Gadget):         pass
class LoadConst(Gadget):       pass
class Arithmetic(Gadget):      pass
class LoadMem(Gadget):         pass
class LoadStack(Gadget):       pass
class StoreMem(Gadget):        pass
class ArithmeticLoad(Gadget):  pass
class ArithmeticStore(Gadget): pass


class GadgetTypes(enum.Enum):
  (
    UNKNOWN,
    #JUMP,              # Jump to address / register
    MOV_REG,           # OutReg <- InReg
    LOAD_CONST,        # OutReg <- Constant
    ARITHMETIC,        # OutReg <- InReg1 operator InReg2
    LOAD_MEM,          # OutReg <- Mem[Address or Register]
    LOAD_STACK,        # OutReg <- Mem[rsp + offset]
    STORE_MEM,         # Mem[Address or Register] = InReg
    ARITHMETIC_LOAD,   # OutReg <- OutReg operator M[AddrReg or Register]
    ARITHMETIC_STORE,  # Mem[AddrReg or Register] <- Mem[AddrReg or Register] operator InReg
  ) = range(9)

  CLASSES = { MOV_REG : MoveReg, LoadConst : LoadConst, ARITHMETIC : Arithmetic, LOAD_MEM : LoadMem, LOAD_STACK : LoadStack, 
    STORE_MEM : StoreMem, ARITHMETIC_LOAD : ArithmeticLoad, ARITHMETIC_STORE : ArithmeticStore }
  def __init__(self, type_enum, *params):
    return self.CLASSES[type_enum](*params)




if __name__ == "__main__":
  from capstone import *

  disassembler = Cs(CS_ARCH_X86, CS_MODE_64)
  disassembler.detail = True
  tests = [
    (MoveReg,         '\x48\x93\xc3'),                                 # xchg rbx, rax; ret
    (MoveReg,         '\x48\x89\xcb\xc3'),                             # mov rbx,rcx; ret
    (LoadConst,       '\x48\xbb\xff\xee\xdd\xcc\xbb\xaa\x99\x88\xc3'), # movabs rbx,0x8899aabbccddeeff; ret
    (Arithmetic,      '\x48\x01\xc3\xc3'),                             # add rbx, rax; reg
    (LoadMem,         '\x48\x8b\x43\x08\xc3'),                         # mov rax,QWORD PTR [rbx+0x8]; ret
    (LoadStack,       '\x48\x8b\x44\x24\x08\xc3'),                     # mov rax,QWORD PTR [rsp+0x8]; ret
    (LoadStack,       '\x5e\xc3'),                                     # pop rsi; ret
    (LoadStack,       '\x5e\xc2\x10\x00'),                             # pop rsi; ret 16
    (StoreMem,        '\x48\x89\x03\xc3'),                             # mov QWORD PTR [rbx],rax; ret
    (StoreMem,        '\x48\x89\x43\x08\xc3'),                         # mov QWORD PTR [rbx+0x8],rax; ret
    (StoreMem,        '\x48\x89\x44\x24\x08\xc3'),                     # mov QWORD PTR [rsp+0x8],rax; ret
    (ArithmeticLoad,  '\x48\x03\x44\x24\x08\xc3'),                     # add rax,QWORD PTR [rsp+0x8]
    (ArithmeticStore, '\x48\x01\x43\xf8\xc3'),                         # add QWORD PTR [rbx-0x8],rax; ret
    (type(None),      '\x48\x39\xeb\xc3'),                             # cmp rbx, rbp; ret
    (type(None),      '\x5e'),                                         # pop rsi
    (type(None),      '\x8b\x04\xc5\xc0\x32\x45\x00\xc3'),             # mov rax,QWORD PTR [rax*8+0x4532c0]
  ]

  classifier = GadgetClassifier(logging.DEBUG)
  fail = False
  for (class_type, code) in tests:
    g = classifier.create_gadget_from_instructions([x for x in disassembler.disasm(code, 0x400000)]) # Expand the generator
    if type(g) != class_type:
      print "Bad Gadget.  Expected {}, Got {}".format(class_type.__name__, type(g).__name__)
      fail = True
    print g, "\n"

  if fail:
    print "FAILURE!!! One or more incorrectly classified gadgets"

