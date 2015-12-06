import collections, logging, random, sys
from capstone.x86 import *
import z3

from ast import *
import enum

class GadgetClassifier(object):
  NUM_VALIDATIONS = 5

  def __init__(self, log_level = logging.WARNING):
    logging.basicConfig(format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    self.logger = logging.getLogger(self.__class__.__name__)
    self.logger.setLevel(log_level)

    self.instruction_emulators = collections.defaultdict((lambda: self.unknown_instruction), {
      "MOVABS" : self.MOV,
    })

  def create_gadgets_from_instructions(self, insts):
    self.insts = insts
    self.effects = []

    for inst in self.insts:
      inst_name = str(inst.mnemonic).upper()
      try:
        if hasattr(self, inst_name):
          getattr(self, inst_name)(inst)
        else:
          self.instruction_emulators[inst_name](inst)
      except RuntimeError, err:
        self.logger.info(err)
        return []

    return self.get_gadgets()

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

  def execute(self, registers, memory):
    output_memory = {}
    output_registers = {}
    for dst, value in self.effects:
      value = value.compute(registers, memory)
      if type(dst) == Register:
        output_registers[dst.name] = value
      elif type(dst) == Memory:

        address = dst.address.compute(registers, memory)
        output_memory[address] = value
    return output_registers, output_memory

  def check_execution_for_gadget_types(self, inputs, memory, output_registers, output_memory):
    possible_types = []
    if "rip" not in output_registers: # If we can't set rip, then we can't use this gadget
      return possible_types
 
    for oname, ovalue in output_registers.items():
      # Check for LOAD_CONST (it'll get filtered between the multiple rounds)
      possible_types.append((GadgetTypes.LOAD_CONST, [], oname, ovalue))

      for iname, ivalue in inputs.items():
        # Check for MOV_REG
        if ovalue == ivalue:
          possible_types.append((GadgetTypes.MOV_REG, [iname], oname, []))

        if oname == "rip":
          possible_types.append((GadgetTypes.JUMP, [iname], oname, [ovalue - ivalue]))

        # Check for ARITHMETIC
        if iname != oname: # add rbx, rax (where rbx is dst/operand 1 and rax is operand 2)
          continue

        for iname2, ivalue2 in inputs.items():
          if (ovalue == ivalue + ivalue2
              or ovalue == ivalue - ivalue2
              or ovalue == ivalue * ivalue2
              or (ovalue == ivalue & ivalue2 and iname != iname2)
              or (ovalue == ivalue | ivalue2 and iname != iname2)
              or ovalue == ivalue ^ ivalue2):
            possible_types.append((GadgetTypes.ARITHMETIC, [iname, iname2], oname, None))

      for address, value_at_address in memory.items():
        # Check for ARITHMETIC_LOAD
        for reg_input_name, reg_input_value in inputs.items():
          if (   ovalue == reg_input_value + value_at_address
              or ovalue == reg_input_value - value_at_address
              or ovalue == reg_input_value * value_at_address
              or ovalue == reg_input_value & value_at_address 
              or ovalue == reg_input_value | value_at_address
              or ovalue == reg_input_value ^ value_at_address):

            for addr_reg_name, addr_reg_value in inputs.items():
              possible_types.append((GadgetTypes.ARITHMETIC_LOAD, [reg_input_name], oname, [address - addr_reg_value]))

        # Check for LOAD_MEM
        if ovalue == value_at_address:
          for iname, ivalue in inputs.items():
            possible_types.append((GadgetTypes.LOAD_MEM, [iname], oname, [address - ivalue]))

    for address, value in output_memory.items():
      for reg_input_name, reg_input_value in inputs.items():
        # Check for STORE_MEM
        if value == reg_input_value:
          for addr_reg, addr_value in inputs.items():
            possible_types.append((GadgetTypes.STORE_MEM, [addr_reg, reg_input_name], None, [address - addr_value]))

        # Check for ARITHMETIC_STORE
        initial_memory_value = None
        if not address in memory.keys():
          continue

        initial_memory_value = memory[address]
        if (value == initial_memory_value + reg_input_value or value == initial_memory_value - reg_input_value or
            value == initial_memory_value * reg_input_value or value == initial_memory_value & reg_input_value or
            value == initial_memory_value | reg_input_value or value == initial_memory_value ^ reg_input_value):

          for addr_reg_name, addr_reg_value in inputs.items():
            possible_types.append((GadgetTypes.ARITHMETIC_STORE, [addr_reg_name, reg_input_name], None, [address - addr_reg_value]))

    return possible_types

  def get_solver_with_effects(self):
    solver = z3.Solver()
    for dst, value in self.effects:
      solver.add(Equal(dst, value).to_z3())
    return solver

  def validate_and_create_move_reg(self, inputs, output, params, stack_offset, rip_in_stack_offset):
    # TODO validate with z3
    return MoveReg(self.insts, inputs, output, params, self.effects, stack_offset, rip_in_stack_offset)

  def validate_and_create_load_const(self, inputs, output, params, stack_offset, rip_in_stack_offset):
    # TODO validate with z3
    return LoadConst(self.insts, inputs, output, params, self.effects, stack_offset, rip_in_stack_offset)

  def validate_and_create_arithmetic(self, inputs, output, params, stack_offset, rip_in_stack_offset):
    # TODO validate with z3
    return Arithmetic(self.insts, inputs, output, params, self.effects, stack_offset, rip_in_stack_offset)

  def validate_and_create_load_mem(self, inputs, output, params, stack_offset, rip_in_stack_offset):
    # TODO validate with z3
    return LoadMem(self.insts, inputs, output, params, self.effects, stack_offset, rip_in_stack_offset)

  def validate_and_create_store_mem(self, inputs, output, params, stack_offset, rip_in_stack_offset):
    # TODO validate with z3
    return StoreMem(self.insts, inputs, output, params, self.effects, stack_offset, rip_in_stack_offset)

  def validate_and_create_aritmetic_load(self, inputs, output, params, stack_offset, rip_in_stack_offset):
    # TODO validate with z3
    return ArithmeticLoad(self.insts, inputs, output, params, self.effects, stack_offset, rip_in_stack_offset)

  def validate_and_create_aritmetic_store(self, inputs, output, params, stack_offset, rip_in_stack_offset):
    # TODO validate with z3
    return ArithmeticStore(self.insts, inputs, output, params, self.effects, stack_offset, rip_in_stack_offset)

  def validate_and_create_jump(self, inputs, output, params, stack_offset, rip_in_stack_offset):
    # TODO validate with z3
    return Jump(self.insts, inputs, output, params, self.effects, stack_offset, rip_in_stack_offset)

  def get_stack_offset(self):
    inputs = collections.defaultdict(lambda: 0, {})
    memory = collections.defaultdict(lambda: 0, {})
    output_registers, output_memory = self.execute(inputs, memory)
    if "rsp" in output_registers:
      return output_registers["rsp"]
    return 0

  def get_gadgets(self):
    validators = {  GadgetTypes.JUMP             : self.validate_and_create_jump,
                    GadgetTypes.MOV_REG          : self.validate_and_create_move_reg,
                    GadgetTypes.LOAD_CONST       : self.validate_and_create_load_const,
                    GadgetTypes.ARITHMETIC       : self.validate_and_create_arithmetic,
                    GadgetTypes.LOAD_MEM         : self.validate_and_create_load_mem,
                    GadgetTypes.STORE_MEM        : self.validate_and_create_store_mem,
                    GadgetTypes.ARITHMETIC_LOAD  : self.validate_and_create_aritmetic_load,
                    GadgetTypes.ARITHMETIC_STORE : self.validate_and_create_aritmetic_store}

    possible_types = None
    for i in range(self.NUM_VALIDATIONS):
      inputs = collections.defaultdict(lambda: random.randint(0,0x100000), {})
      memory = collections.defaultdict(lambda: random.randint(0,0x100000), {})
      output_registers, output_memory = self.execute(inputs, memory)
      possible_types_this_round = self.check_execution_for_gadget_types(inputs, memory, output_registers, output_memory)

      if possible_types == None:
        possible_types = possible_types_this_round
      else:
        new_possible_types = []
        for possible_type_this_round in possible_types_this_round:
          for possible_type in possible_types:
            if possible_type_this_round == possible_type:
              new_possible_types.append(possible_type)
        possible_types = new_possible_types
    
    gadgets = []
    stack_offset = self.get_stack_offset()
    rip_in_stack_offset = None
    for (gadget_type, inputs, output, params) in possible_types:
      if gadget_type == GadgetTypes.LOAD_MEM and output == "rip" and inputs[0] == "rsp":
        rip_in_stack_offset = params[0]

    for (gadget_type, inputs, output, params) in possible_types:
      if output == "rip" and gadget_type != GadgetTypes.JUMP: continue # Ignore the LOAD_MEM from the ret at the end

      gadget = validators[gadget_type](inputs, output, params, stack_offset, rip_in_stack_offset)
      if gadget != None:
        self.logger.debug("Found %s gadget with inputs %s, output %s, and params %s",
          GadgetTypes.to_string(gadget_type), inputs, output, params)
        gadgets.append(gadget)

    return gadgets

############################################################################################
## Helper Utilities ########################################################################
############################################################################################

  def resolve_register(self, inst, reg_num):
    if reg_num == X86_REG_INVALID:
      return None
    name = str(inst.reg_name(reg_num))
    for (dst, value) in self.effects:
      if type(dst) == Register and dst.is_same_register(name):
        return value
    return Register(name)

  def rsp(self, inst): return self.resolve_register(inst, X86_REG_RSP)
  def rip(self, inst): return self.resolve_register(inst, X86_REG_RIP)

  def resolve_memory(self, inst, op):
    address = self.resolve_register(inst, op.mem.base)
    index = self.resolve_register(inst, op.mem.index)

    if index == None and address == None:
      raise RuntimeError("Gadget uses a constant location that we can't be sure exists (or is marked up by relocations).  Skipping")

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

  def set_operand_value_for_inst(self, value, inst, op_num = 0):
    dst = inst.operands[op_num]
    if dst.type == X86_OP_MEM:
      self.set_operand_value(self.resolve_memory(inst, dst), value)
    else:
      self.set_operand_value(Register(str(inst.reg_name(dst.reg))), value)

  def set_register_value(self, name, value):
    self.set_operand_value(Register(name), value)

############################################################################################
## Instruction Emulators ###################################################################
############################################################################################

  def unknown_instruction(self, inst):
    raise RuntimeError("Unknown instruction: {}".format(inst.mnemonic))

  def binary(self, inst, operand):
    dst, src = self.get_operand_values(inst)
    self.set_operand_value_for_inst(operand(dst, src), inst)

  def ADD(self, inst): self.binary(inst, Add)
  def SUB(self, inst): self.binary(inst, Sub)
  def AND(self, inst): self.binary(inst, BitwiseAnd)
  def  OR(self, inst): self.binary(inst, BitwiseOr)
  def XOR(self, inst): self.binary(inst, BitwiseXor)

  def POP(self, inst):
    dst = self.get_operand_values(inst)[0]
    rsp = self.rsp(inst)
    self.set_operand_value_for_inst(Memory(rsp, 8), inst)
    self.set_register_value("rsp", Add(rsp, Const(8)))

  def PUSH(self, inst):
    src = self.get_operand_values(inst)[0]
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
    self.set_operand_value_for_inst(src, inst)

  def XCHG(self, inst):
    dst, src = self.get_operand_values(inst)
    self.set_operand_value_for_inst(src, inst, 0)
    self.set_operand_value_for_inst(dst, inst, 1)

  def NOP(self, inst):
    pass

  def JMP(self, inst):
    src = self.get_operand_values(inst)[0]
    rip = self.rip(inst)
    self.set_operand_value(rip, src)

class Gadget(object):
  def __init__(self, insts, inputs, output, params, effects, stack_offset, rip_in_stack_offset):
    self.insts = insts
    self.address = insts[0].address
    self.inputs = inputs
    self.output = output
    self.params = params
    self.effects = effects
    self.stack_offset = stack_offset
    self.rip_in_stack_offset = rip_in_stack_offset

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
    return self.output in name

  def clobbers_registers(self, names):
    for name in names:
      if self.clobbers_registers(name):
        return True
    return False

  def uses_register(self, name):
    for an_input in self.inputs:
      if type(an_input) == Register and an_input.name == name:
        return True
    return self.clobbers_register(name) or (type(self.output) == Register and self.output.name == name)

  def complexity(self):
    return len(self.clobber) + (1 if self.stack_offset - 8 != self.rip_in_stack_offset else 0)

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

class Jump(Gadget): pass
class MoveReg(Gadget):         pass
class LoadConst(Gadget):       pass
class Arithmetic(Gadget):      pass
class LoadMem(Gadget):         pass
class StoreMem(Gadget):        pass
class ArithmeticLoad(Gadget):  pass
class ArithmeticStore(Gadget): pass


class GadgetTypes(enum.Enum):
  (
    UNKNOWN,
    JUMP,              # Jump to address / register
    MOV_REG,           # OutReg <- InReg
    LOAD_CONST,        # OutReg <- Constant
    ARITHMETIC,        # OutReg <- InReg1 operator InReg2
    LOAD_MEM,          # OutReg <- Mem[Address or Register]
    STORE_MEM,         # Mem[Address or Register] = InReg
    ARITHMETIC_LOAD,   # OutReg <- OutReg operator M[AddrReg or Register]
    ARITHMETIC_STORE,  # Mem[AddrReg or Register] <- Mem[AddrReg or Register] operator InReg
  ) = range(9)

  CLASSES = { JUMP : Jump, MOV_REG : MoveReg, LoadConst : LoadConst, ARITHMETIC : Arithmetic, LOAD_MEM : LoadMem,
    STORE_MEM : StoreMem, ARITHMETIC_LOAD : ArithmeticLoad, ARITHMETIC_STORE : ArithmeticStore }
  def __init__(self, type_enum, *params):
    return self.CLASSES[type_enum](*params)




if __name__ == "__main__":
  from capstone import *

  disassembler = Cs(CS_ARCH_X86, CS_MODE_64)
  disassembler.detail = True
  tests = [
    ({Jump : 1},            '\xff\xe0'),                                     # jmp rax
    ({MoveReg : 2},         '\x48\x93\xc3'),                                 # xchg rbx, rax; ret
    ({MoveReg : 1},         '\x48\x89\xcb\xc3'),                             # mov rbx,rcx; ret
    ({LoadConst : 1},       '\x48\xbb\xff\xee\xdd\xcc\xbb\xaa\x99\x88\xc3'), # movabs rbx,0x8899aabbccddeeff; ret
    ({Arithmetic : 1},      '\x48\x01\xc3\xc3'),                             # add rbx, rax; reg
    ({LoadMem : 1},         '\x48\x8b\x43\x08\xc3'),                         # mov rax,QWORD PTR [rbx+0x8]; ret
    ({StoreMem : 1},        '\x48\x89\x03\xc3'),                             # mov QWORD PTR [rbx],rax; ret
    ({StoreMem : 1},        '\x48\x89\x43\x08\xc3'),                         # mov QWORD PTR [rbx+0x8],rax; ret
    ({StoreMem : 1},        '\x48\x89\x44\x24\x08\xc3'),                     # mov QWORD PTR [rsp+0x8],rax; ret
    ({ArithmeticLoad : 1},  '\x48\x03\x44\x24\x08\xc3'),                     # add rax,QWORD PTR [rsp+0x8]
    ({ArithmeticStore : 1}, '\x48\x01\x43\xf8\xc3'),                         # add QWORD PTR [rbx-0x8],rax; ret
    ({},                    '\x48\x39\xeb\xc3'),                             # cmp rbx, rbp; ret
    ({},                    '\x5e'),                                         # pop rsi
    ({},                    '\x8b\x04\xc5\xc0\x32\x45\x00\xc3'),             # mov rax,QWORD PTR [rax*8+0x4532c0]
    ({LoadMem : 1, LoadConst : 1}, '\x59\x48\x89\xcb\x48\xc7\xc1\x05\x00\x00\x00\xc3'), # pop rcx; mov rbx,rcx; mov rcx,0x5; ret
  ]

  classifier = GadgetClassifier(logging.DEBUG)
  fail = False
  for (expected_types, code) in tests:
    gadgets = classifier.create_gadgets_from_instructions([x for x in disassembler.disasm(code, 0x400000)]) # Expand the generator
    types = {}

    for g in gadgets:
      if type(g) not in types: types[type(g)] = 0
      types[type(g)] += 1

    if types != expected_types:
      print "\nWrong Types Found.  Expected {}, got {}".format(
        ",".join(["{} {}".format(t.__name__, c) for t,c in expected_types.items()]),
        ",".join(["{} {}".format(t.__name__, c) for t,c in types.items()]))

      print "Gadgets:"
      for g in gadgets:
        print g
      print "\n"

  if fail:
    print "FAILURE!!! One or more incorrectly classified gadgets"

