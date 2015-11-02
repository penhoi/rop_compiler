from capstone.x86 import *
import collections

from ast import *

# A few register objects for convenience
rsp = Register("rsp")
rip = Register("rip")

class Gadget(object):

  def __init__(self, insts):
    self.instruction_emulators = collections.defaultdict((lambda: self.unknown_instruction), {
      "ret" : self.ret,
      "add" : self.add, "sub" : self.sub,
      "pop" : self.pop, "push" : self.push,
    })
    self.insts = insts
    self.get_effects()

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
    return "0x{:x}: {} / effects: {}".format(address, output, effects)

  def get_effects(self):
    self.effects = []
    for inst in self.insts:
      self.instruction_emulators[inst.mnemonic](inst)

############################################################################################
## Helper Utilities ########################################################################
############################################################################################

  def resolve_register(self, inst, reg_num):
      if reg_num == X86_REG_INVALID:
        return None
      return Register(inst.reg_name(reg_num))

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

  def set_operand_value(self, dst, value):
    self.effects.append((dst, value))

############################################################################################
## Instruction Emulators ###################################################################
############################################################################################

  def unknown_instruction(self, inst):
    print "UNKNOWN"
    raise RuntimeError("Unknown instruction: {}".format(inst.mnemonic))

  def binary(self, inst, operand):
    dst, src = self.get_operand_values(inst)
    self.set_operand_value(dst, operand(dst, src))

  def add(self, inst): self.binary(inst, Add)
  def sub(self, inst): self.binary(inst, Sub)

  def pop(self, inst):
    dst = self.get_operand_values(inst)[0]
    self.set_operand_value(dst, Memory(rsp, 8))
    self.set_operand_value(rsp, Add(rsp, 8))

  def push(self, inst):
    src = self.get_operand_values(inst)
    self.set_operand_value(Memory(rsp, 8), src)
    self.set_operand_value(rsp, Sub(rsp, 8))

  def ret(self, inst):
    self.set_operand_value(rip, Memory(rsp, 8))
    self.set_operand_value(rsp, Add(rsp, 8))

if __name__ == "__main__":
  from capstone import *

  disassembler = Cs(CS_ARCH_X86, CS_MODE_64)
  disassembler.detail = True
  codes = [
    '\x00\x48\x01\xc3', # add byte ptr [rax + 1], cl; ret
    '\x5e\xc3',         # pop rsi; ret
  ]
  for code in codes:
    g = Gadget([x for x in disassembler.disasm(code, 0x400000)]) # Expand the generator
    print g

