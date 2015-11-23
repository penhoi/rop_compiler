from capstone.x86 import *
import collections

from ast import *
import enum

class GadgetTypes(enum.Enum):
  (
    UNKNOWN,
    JUMP,              # Jump to address / register
    MOV_REG,           # OutReg <- InReg
    LOAD_CONST,        # OutReg <- Constant
    ARITHMETIC,        # OutReg <- InReg1 operator InReg2
    LOAD_MEM,          # OutReg <- Mem[Address or Register]
    LOAD_STACK,        # OutReg <- Mem[rsp + offset]
    STORE_MEM,         # Mem[Address or Register] = InReg
    ARITHMETIC_LOAD,   # OutReg <- OutReg operator M[AddrReg or Register]
    ARITHMETIC_STORE,  # Mem[AddrReg or Register] <- Mem[AddrReg or Register] operator InReg
  ) = range(10)

class Gadget(object):

  def __init__(self, insts):
    self.instruction_emulators = collections.defaultdict((lambda: self.unknown_instruction), {
      "ret" : self.RET,
      "add" : self.ADD, "sub"  : self.SUB,
      "and" : self.AND, "or"   : self.OR,
      "xor" : self.XOR,
      "pop" : self.POP, "push" : self.PUSH,
      "mov" : self.MOV, "xchg" : self.XCHG,
      "nop" : self.NOP,
    })
    self.insts = insts
    self.set_effects()
    self.set_type()
    self.set_next_stack()

  def __str__(self):
    output = ""
    address = 0
    for inst in self.insts:
      if address == 0: address = inst.address
      if output != "": output += "; "
      output += "{} {}".format(inst.mnemonic, inst.op_str)
    effects = ""
    for (dst, value) in self.effects:
      if effects != "": effects += "; "
      effects += "{} = {}".format(dst, value)
    return "0x{:x} {}: {} / effects: {}".format(address, GadgetTypes.to_string(self.gadget_type), output, effects)

  def set_effects(self):
    self.effects = []
    for inst in self.insts:
      self.instruction_emulators[inst.mnemonic](inst)

  def set_next_stack(self):
    """We'll need to know how to get the stack value after this gadget, so find it here"""
    self.next_stack = None
    for (dst, value) in self.effects:
      if type(dst) == Register and dst.name == "rsp":
        self.next_stack = value

  def is_address_based_off_stack(self, address):
    registers = self.get_registers_in_address(address)

    # TODO consider cases where the address is something like [rsp+rax]
    if len(registers) == 1 and registers[0].name == "rsp":
      return True
    return False

  def get_leaf_nodes(self, value):
    if type(value) == Const or type(value) == Register:
      return [value]
    elif type(value) == Memory:
      return self.get_leaf_nodes(value.address)

    if issubclass(value.__class__, Operand):
      leafs = []
      for operand in value.operands:
        leafs.extend(self.get_leaf_nodes(operand)) 
      return leafs

    raise RuntimeError("Unknown type in get_leaf_nodes {}".format(type(address)))

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

  def is_same_memory(self, memory1, memory2):
    # TODO convert this to use the solver to determine this so it can allow more types

    address1, address2 = memory1.address, memory2.address
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

    if None in [reg1, reg2] or type(const1) != type(const2): # Allow
      return

    return reg1.name == reg2.name and (None in [const1, const2] or const1.value == const2.value)

  def set_type(self):
    self.gadget_type = GadgetTypes.UNKNOWN
    memory_writes = []
    register_writes = []
    for (dst, value) in self.effects:
      if type(dst) == Memory:
        memory_writes.append((dst,value))
      elif type(dst) == Register:
        register_writes.append((dst,value))

    if len(memory_writes) > 1: # A little semantic, we don't want to deal with multiple memory writes
      return

    if len(register_writes) > 3: # TODO for now don't deal with anything beyond writing to one register
      return

    for (dst, value) in register_writes:
      if dst.name == "rsp" or dst.name == "rip":
        continue

      if type(value) == Register:
        self.gadget_type = GadgetTypes.MOV_REG
      elif type(value) == Const:
        self.gadget_type = GadgetTypes.LOAD_CONST
      elif type(value) == Memory:
        if self.is_address_based_off_stack(value.address):
          self.gadget_type = GadgetTypes.LOAD_STACK
        else:
          self.gadget_type = GadgetTypes.LOAD_MEM
      elif issubclass(value.__class__, Operand):
        leafs = self.get_leaf_nodes(value)
        if len(leafs) == 2:
          if type(leafs[0]) == Register and type(leafs[1]) == Register:
            self.gadget_type = GadgetTypes.ARITHMETIC
          else:
            dst_found = False
            non_dst = None
            for operand in value.operands:
              if type(operand) == Register and operand.name == dst.name:
                dst_found = True
              else:
                non_dst = operand

            if (dst_found and self.is_simple_memory_value(non_dst)):
              self.gadget_type = GadgetTypes.ARITHMETIC_LOAD

    for (dst, value) in memory_writes:
      if not self.is_simple_memory_value(dst):
        continue

      if type(value) is Register:
        self.gadget_type = GadgetTypes.STORE_MEM
      elif issubclass(value.__class__, Operand):
        possible_dst = non_dst = None
        if (type(value.operands[0]) == Memory and type(value.operands[1]) == Register):
          possible_dst, non_dst = value.operands
        elif (type(value.operands[0]) == Register and type(value.operands[1]) == Memory):
          non_dst, possible_dst = value.operands

        if possible_dst != None and self.is_same_memory(dst, possible_dst):
          self.gadget_type = GadgetTypes.ARITHMETIC_STORE

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
    return Register(name)

  def rsp(self, inst): return self.resolve_register(inst, X86_REG_RSP)
  def rip(self, inst): return self.resolve_register(inst, X86_REG_RIP)

  def resolve_memory(self, inst, op):
    address = self.resolve_register(inst, op.mem.base)
    index = self.resolve_register(inst, op.mem.index)
    if index != None:
      if op.mem.scale != 1:
        index = Mult(index, Const(op.mem.scale))
      address = Add(address, index)
    if op.mem.disp != 0:
      address = Add(address, Const(op.mem.disp))
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
      if type(destination) == Register and destination.is_same_register(dst.name):
        remove_this = (destination, old_value)
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
    self.set_register_value("rsp", Add(rsp, 8))

  def PUSH(self, inst):
    src = self.get_operand_values(inst)
    rsp = self.rsp(inst)
    self.set_operand_value(Memory(rsp, 8), src)
    self.set_register_value("rsp", Sub(rsp, 8))

  def RET(self, inst):
    rsp = self.rsp(inst)
    rip = self.rip(inst)

    amount = self.get_operand_values(inst)
    stack_diff = 8
    if len(amount) != 0:
      stack_diff += amount[0].value # will always be an immediate

    self.set_operand_value(rip, Memory(rsp, 8))
    self.set_register_value("rsp", Add(rsp, stack_diff))

  def MOV(self, inst):
    dst, src = self.get_operand_values(inst)
    self.set_operand_value(dst, src)

  def XCHG(self, inst):
    dst, src = self.get_operand_values(inst)
    self.set_operand_value(dst, src)
    self.set_operand_value(src, dst)

  def NOP(self, inst):
    pass


if __name__ == "__main__":
  from capstone import *

  disassembler = Cs(CS_ARCH_X86, CS_MODE_64)
  disassembler.detail = True
  codes = [
    '\x00\x48\x01\xc3',         # add byte ptr [rax + 1], cl; ret
    '\x5e\xc3',                 # pop rsi; ret
    '\x48\x93\xc3',             # xchg rbx, rax; ret
    '\x5e\xc2\x10\x00',         # pop rsi; ret 16
    '\x48\x89\x03\xc3',         # mov QWORD PTR [rbx],rax; ret
    '\x48\x89\x43\x08\xc3',     # mov QWORD PTR [rbx+0x8],rax; ret
    '\x48\x01\x43\xf8\xc3',     # add QWORD PTR [rbx-0x8],rax; ret
    '\x48\x89\x44\x24\x08',     # mov QWORD PTR [rsp+0x8],rax
    '\x48\x8b\x44\x24\x08',     # mov rax,QWORD PTR [rsp+0x8]
    '\x48\x8b\x43\x08',         # mov rax,QWORD PTR [rbx+0x8]
  ]
  for code in codes:
    g = Gadget([x for x in disassembler.disasm(code, 0x400000)]) # Expand the generator
    print g

