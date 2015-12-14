# This file holds the gadget classifier and various gadget type classes.

import collections, logging, random, sys
from capstone.x86 import *
import z3

from ast import *
import enum

class GadgetClassifier(object):
  """This class is used to convert a set of instructions that represent a gadget into a Gadget class of the appropriate type"""

  """The number of times to emulate a gadget when classifying it"""
  NUM_VALIDATIONS = 5

  def __init__(self, log_level = logging.WARNING):
    logging.basicConfig(format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    self.logger = logging.getLogger(self.__class__.__name__)
    self.logger.setLevel(log_level)

    # Holds any instruction emulators that aren't named the same as the instruction mnemonic
    self.instruction_emulators = collections.defaultdict((lambda: self.unknown_instruction), {
      "MOVABS" : self.MOV,
    })

  def create_gadgets_from_instructions(self, insts):
    """This function takes a list of capstone instructions and converts them into a list of gadgets with the appropriate types.
    Note that a single set of instructions can be more than one gadget typer, and thus a list is returned"""
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
        # RuntimeError's are thrown whenever we detect a gadget is unusable (Memory Reads from Constants, Bad instructions, etc)
        # Upon receiving an error, give up on this set of instructions
        self.logger.info(err)
        return []

    return self.get_gadgets()

  def execute(self, registers, memory):
    """Given a dictionary of input registers and memory values, emulate the current gadget's instructions and return any
      writes to registers or memory (as two dictionaries)"""
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
    """Given the results of an emulation of a set of instructions, check the results to determine any potential gadget types and
      the associated inputs, outputs, and parameters.  This is done by checking the results to determine any of the
      preconditions that the gadget follows for this execution.  This method returns a list of the format
      (Gadget Type, list of inputs, output, list of parameters).  Note the returned potential gadgets are a superset of the 
      actual gadgets, i.e. some of the returned ones are merely coincidences in the emulation, and not true gadgets."""
    possible_types = []
    if "rip" not in output_registers: # If we can't set rip, then we can't use this gadget
      return possible_types
 
    for oname, ovalue in output_registers.items():
      # Check for LOAD_CONST (it'll get filtered between the multiple rounds)
      possible_types.append((LoadConst, [], oname, ovalue))

      for iname, ivalue in inputs.items():
        # Check for MOV_REG
        if ovalue == ivalue:
          possible_types.append((MoveReg, [iname], oname, []))

        if oname == "rip":
          possible_types.append((Jump, [iname], oname, [ovalue - ivalue]))

        # Check for ARITHMETIC
        if iname != oname: # add rbx, rax (where rbx is dst/operand 1 and rax is operand 2)
          continue

        for iname2, ivalue2 in inputs.items():
          if ovalue == ivalue + ivalue2:
            possible_types.append((AddGadget, [iname, iname2], oname, None))
          if ovalue == ivalue - ivalue2:
            possible_types.append((SubGadget, [iname, iname2], oname, None))
          if ovalue == ivalue * ivalue2:
            possible_types.append((MulGadget, [iname, iname2], oname, None))
          if ovalue == ivalue & ivalue2 and iname != iname2:
            possible_types.append((AndGadget, [iname, iname2], oname, None))
          if ovalue == ivalue | ivalue2 and iname != iname2:
            possible_types.append((OrGadget, [iname, iname2], oname, None))
          if ovalue == ivalue ^ ivalue2:
            possible_types.append((XorGadget, [iname, iname2], oname, None))

      for address, value_at_address in memory.items():
        # Check for ARITHMETIC_LOAD
        for reg_input_name, reg_input_value in inputs.items():
          for addr_reg_name, addr_reg_value in inputs.items():
            if ovalue == reg_input_value + value_at_address:
              possible_types.append((LoadAddGadget, [reg_input_name], oname, [address - addr_reg_value]))
            if ovalue == reg_input_value - value_at_address:
              possible_types.append((LoadSubGadget, [reg_input_name], oname, [address - addr_reg_value]))
            if ovalue == reg_input_value * value_at_address:
              possible_types.append((LoadMulGadget, [reg_input_name], oname, [address - addr_reg_value]))
            if ovalue == reg_input_value & value_at_address: 
              possible_types.append((LoadAndGadget, [reg_input_name], oname, [address - addr_reg_value]))
            if ovalue == reg_input_value | value_at_address:
              possible_types.append((LoadOrGadget, [reg_input_name], oname, [address - addr_reg_value]))
            if ovalue == reg_input_value ^ value_at_address:
              possible_types.append((LoadXorGadget, [reg_input_name], oname, [address - addr_reg_value]))

        # Check for LOAD_MEM
        if ovalue == value_at_address:
          for iname, ivalue in inputs.items():
            possible_types.append((LoadMem, [iname], oname, [address - ivalue]))

    for address, value in output_memory.items():
      for reg_input_name, reg_input_value in inputs.items():
        # Check for STORE_MEM
        if value == reg_input_value:
          for addr_reg, addr_value in inputs.items():
            possible_types.append((StoreMem, [addr_reg, reg_input_name], None, [address - addr_value]))

        # Check for ARITHMETIC_STORE
        initial_memory_value = None
        if not address in memory.keys():
          continue

        initial_memory_value = memory[address]

        for addr_reg_name, addr_reg_value in inputs.items():
          if value == initial_memory_value + reg_input_value:
            possible_types.append((StoreAddGadget, [addr_reg_name, reg_input_name], None, [address - addr_reg_value]))
          if value == initial_memory_value - reg_input_value:
            possible_types.append((StoreSubGadget, [addr_reg_name, reg_input_name], None, [address - addr_reg_value]))
          if value == initial_memory_value * reg_input_value:
            possible_types.append((StoreMulGadget, [addr_reg_name, reg_input_name], None, [address - addr_reg_value]))
          if value == initial_memory_value & reg_input_value:
            possible_types.append((StoreAndGadget, [addr_reg_name, reg_input_name], None, [address - addr_reg_value]))
          if value == initial_memory_value | reg_input_value:
            possible_types.append((StoreOrGadget, [addr_reg_name, reg_input_name], None, [address - addr_reg_value]))
          if value == initial_memory_value ^ reg_input_value:
            possible_types.append((StoreXorGadget, [addr_reg_name, reg_input_name], None, [address - addr_reg_value]))

    return possible_types

  def get_solver_with_effects(self):
    """Gets a z3 solver instance that has been setup with equations representing the effects of the current instructions"""
    solver = z3.Solver()
    for dst, value in self.effects:
      solver.add(Equal(dst, value).to_z3())
    return solver

  def get_stack_offset(self):
    """Returns the stack offset (difference in stack at the beginning and end of a gadget) by emulating the current instructions"""
    inputs = collections.defaultdict(lambda: 0, {})
    memory = collections.defaultdict(lambda: 0, {})
    output_registers, output_memory = self.execute(inputs, memory)
    if "rsp" in output_registers:
      return output_registers["rsp"]
    return 0

  def get_gadgets(self):
    """Emulates the current instructions to determine any gadgets within them.  This method returns a list of the found Gadgets"""

    possible_types = None
    for i in range(self.NUM_VALIDATIONS):
      inputs = collections.defaultdict(lambda: random.randint(0,0x100000), {})
      memory = collections.defaultdict(lambda: random.randint(0,0x100000), {})
      output_registers, output_memory = self.execute(inputs, memory)
      possible_types_this_round = self.check_execution_for_gadget_types(inputs, memory, output_registers, output_memory)

      if possible_types == None:
        possible_types = possible_types_this_round
      else: # For each round, only keep the potential gadgets that are in each round
        new_possible_types = []
        for possible_type_this_round in possible_types_this_round:
          for possible_type in possible_types:
            if possible_type_this_round == possible_type:
              new_possible_types.append(possible_type)
        possible_types = new_possible_types
    
    gadgets = []
    stack_offset = self.get_stack_offset()
    rip_in_stack_offset = None
    for (gadget_type, inputs, output, params) in possible_types: # Find the offset of rip in the stack for these gadgets
      if gadget_type == LoadMem and output == "rip" and inputs[0] == "rsp":
        rip_in_stack_offset = params[0]

    for (gadget_type, inputs, output, params) in possible_types:
      if output == "rip" and gadget_type != Jump: continue # Ignore the LoadMem gadget from the ret at the end
      if rip_in_stack_offset == None and gadget_type != Jump: continue # Except for Jump, all the gadgets must load rip from the stack

      gadget = gadget_type(self.insts, inputs, output, params, self.effects, stack_offset, rip_in_stack_offset)
      if gadget != None and gadget.validate():
        self.logger.debug("Found %s gadget with inputs %s, output %s, and params %s", gadget_type.__name__, inputs, output, params)
        gadgets.append(gadget)

    return gadgets

############################################################################################
## Instruction Helper Utilities ############################################################
############################################################################################

  def resolve_register(self, inst, reg_num):
    """Given a capstone instruction and a register number, return the associated Register class with it"""
    if reg_num == X86_REG_INVALID:
      return None
    name = str(inst.reg_name(reg_num))
    for (dst, value) in self.effects:
      if type(dst) == Register and dst.is_same_register(name):
        return value
    return Register(name)

  # Two helper methods to return the rsp and rip Registers
  def rsp(self, inst): return self.resolve_register(inst, X86_REG_RSP)
  def rip(self, inst): return self.resolve_register(inst, X86_REG_RIP)

  def resolve_memory(self, inst, op):
    """Given a capstone instruction and memory operand, convert it to the associated AST value"""
    address = self.resolve_register(inst, op.mem.base)
    index = self.resolve_register(inst, op.mem.index)

     # We don't want any gadgets with constant memory reads/writes, so throw an exception
    if index == None and address == None: # It's caught higher up, and causes the gadget to be skipped
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
    """Given a capstone instruction and operand, return the associated AST value for it"""
    if op.type == X86_OP_IMM:
      return Const(op.imm)
    elif op.type == X86_OP_REG:
      return self.resolve_register(inst, op.reg)
    elif op.type == X86_OP_MEM:
      return self.resolve_memory(inst, op)
    raise RuntimeError("Unknown operand type: {}".format(op.type))

  def get_operand_values(self, inst):
    """Given a capstone instruction, convert all of the capstone operands to AST values"""
    return [self.get_operand_value(inst, op) for op in inst.operands]

  def set_operand_value(self, dst, new_value):
    """Given a AST value representing the destination, set the value associated with it."""
    remove_this = None
    for (destination, old_value) in self.effects:
      if type(destination) == Register and type(dst) == Register and destination.is_same_register(dst.name):
        remove_this = (destination, old_value)
      # TODO detect memory overwrites here
    if remove_this != None:
      self.effects.remove(remove_this)
    self.effects.append((dst, new_value))

  def set_operand_value_for_inst(self, value, inst, op_num = 0):
    """Given an AST value and a capstone instruction and operand number, set the specified operand's value to the AST value."""
    dst = inst.operands[op_num]
    if dst.type == X86_OP_MEM:
      self.set_operand_value(self.resolve_memory(inst, dst), value)
    else:
      self.set_operand_value(Register(str(inst.reg_name(dst.reg))), value)

  def set_register_value(self, name, value):
    """A convenience method that takes a register name and AST value and sets the specified Register's to the AST value"""
    self.set_operand_value(Register(name), value)

############################################################################################
## Instruction Emulators ###################################################################
############################################################################################

  def unknown_instruction(self, inst):
    """Raises a RuntimeError. Used to signify that the current instructions include an instruction we don't know how to emulate"""
    raise RuntimeError("Unknown instruction: {}".format(inst.mnemonic))

  def binary(self, inst, operand):
    """The instruction emulator for any of the binary instructions.  Given an instruction and the associated AST operation,
      emulate the instruction"""
    dst, src = self.get_operand_values(inst)
    self.set_operand_value_for_inst(operand(dst, src), inst)

  # Simple methods that emulate the binary instruction operations
  def ADD(self, inst): self.binary(inst, Add)
  def SUB(self, inst): self.binary(inst, Sub)
  def AND(self, inst): self.binary(inst, BitwiseAnd)
  def  OR(self, inst): self.binary(inst, BitwiseOr)
  def XOR(self, inst): self.binary(inst, BitwiseXor)

  def POP(self, inst):
    """The instruction emulator for the POP instruction"""
    dst = self.get_operand_values(inst)[0]
    rsp = self.rsp(inst)
    self.set_operand_value_for_inst(Memory(rsp, 8), inst)
    self.set_register_value("rsp", Add(rsp, Const(8)))

  def PUSH(self, inst):
    """The instruction emulator for the PUSH instruction"""
    src = self.get_operand_values(inst)[0]
    rsp = self.rsp(inst)
    self.set_operand_value(Memory(rsp, 8), src)
    self.set_register_value("rsp", Sub(rsp, Const(8)))

  def RET(self, inst):
    """The instruction emulator for the RET instruction"""
    rsp = self.rsp(inst)
    rip = self.rip(inst)

    amount = self.get_operand_values(inst)
    stack_diff = 8
    if len(amount) != 0:
      stack_diff += amount[0].value # will always be an immediate

    self.set_operand_value(rip, Memory(rsp, 8))
    self.set_register_value("rsp", Add(rsp, Const(stack_diff)))

  def MOV(self, inst):
    """The instruction emulator for the MOV and MOVABS instruction"""
    dst, src = self.get_operand_values(inst)
    self.set_operand_value_for_inst(src, inst)

  def XCHG(self, inst):
    """The instruction emulator for the XCHG instruction"""
    dst, src = self.get_operand_values(inst)
    self.set_operand_value_for_inst(src, inst, 0)
    self.set_operand_value_for_inst(dst, inst, 1)

  def NOP(self, inst):
    """The instruction emulator for the NOP instruction"""
    pass

  def JMP(self, inst):
    """The instruction emulator for the JMP instruction"""
    src = self.get_operand_values(inst)[0]
    rip = self.rip(inst)
    self.set_operand_value(rip, src)

class Gadget(object):
  """This class wraps a set of instructions and holds the associated metadata that makes up a gadget"""

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
    """Check if the gadget clobbers the specified register"""
    for clobber in self.clobber:
      if type(clobber) == Register and clobber.name == name:
        return True
    return self.output in name

  def clobbers_registers(self, names):
    """Check if the gadget clobbers any of the specified registers"""
    for name in names:
      if self.clobbers_register(name):
        return True
    return False

  def uses_register(self, name):
    """Check if the gadget uses the specified register as input"""
    for an_input in self.inputs:
      if type(an_input) == Register and an_input.name == name:
        return True
    return self.clobbers_register(name) or (type(self.output) == Register and self.output.name == name)

  def complexity(self):
    """Return a rough complexity measure for a gadget that can be used to select the best gadget in a set.  Our simple formula
      is based on the number of clobbered registers, and if a normal return (i.e. with no immediate is used).  The stack decider
      helps to priorize gadgets that use less stack space (and thus can fit in smaller buffers)."""
    return len(self.clobber) + (1 if self.stack_offset - 8 != self.rip_in_stack_offset else 0)

  def to_statements(self):
    """Returns a list of AST statements that define the effects of the gadget"""
    statements = []
    for (dst,value) in self.effects:
      if type(dst) == Register:
        statements.append(Equal(Register(dst.name, "_output"), value))
      else:
        statements.append(Store(dst.address, value))
    return statements

  def validate(self):
    """This method validates the inputs, output, and parameters with z3 to ensure it follows the gadget type's preconditions"""
    # TODO validate the gadget type with z3
    return True

# The various Gadget types
class Jump(Gadget):            pass
class MoveReg(Gadget):         pass
class LoadConst(Gadget):       pass
class LoadMem(Gadget):         pass
class Arithmetic(Gadget):      pass
class StoreMem(Gadget):        pass
class ArithmeticLoad(Gadget):  pass
class ArithmeticStore(Gadget): pass

# Split up the Arithmetic gadgets, so they're easy to search for when you are searching for a specific one
class AddGadget(Arithmetic):   pass
class SubGadget(Arithmetic):   pass
class MulGadget(Arithmetic):   pass
class AndGadget(Arithmetic):   pass
class OrGadget(Arithmetic):    pass
class XorGadget(Arithmetic):   pass

# Split up the Arithmetic Load gadgets, so they're easy to search for when you are searching for a specific one
class LoadAddGadget(ArithmeticLoad):   pass
class LoadSubGadget(ArithmeticLoad):   pass
class LoadMulGadget(ArithmeticLoad):   pass
class LoadAndGadget(ArithmeticLoad):   pass
class LoadOrGadget(ArithmeticLoad):    pass
class LoadXorGadget(ArithmeticLoad):   pass

# Split up the Arithmetic Store gadgets, so they're easy to search for when you are searching for a specific one
class StoreAddGadget(ArithmeticStore):   pass
class StoreSubGadget(ArithmeticStore):   pass
class StoreMulGadget(ArithmeticStore):   pass
class StoreAndGadget(ArithmeticStore):   pass
class StoreOrGadget(ArithmeticStore):    pass
class StoreXorGadget(ArithmeticStore):   pass

if __name__ == "__main__":
  from capstone import *

  # A simple set of tests to ensure we can correctly classify some example gadgets
  disassembler = Cs(CS_ARCH_X86, CS_MODE_64)
  disassembler.detail = True
  tests = [
    ({Jump : 1},            '\xff\xe0'),                                                # jmp rax
    ({MoveReg : 2},         '\x48\x93\xc3'),                                            # xchg rbx, rax; ret
    ({MoveReg : 1},         '\x48\x89\xcb\xc3'),                                        # mov rbx,rcx; ret
    ({LoadConst : 1},       '\x48\xbb\xff\xee\xdd\xcc\xbb\xaa\x99\x88\xc3'),            # movabs rbx,0x8899aabbccddeeff; ret
    ({AddGadget : 1},       '\x48\x01\xc3\xc3'),                                        # add rbx, rax; reg
    ({LoadMem : 1},         '\x48\x8b\x43\x08\xc3'),                                    # mov rax,QWORD PTR [rbx+0x8]; ret
    ({StoreMem : 1},        '\x48\x89\x03\xc3'),                                        # mov QWORD PTR [rbx],rax; ret
    ({StoreMem : 1},        '\x48\x89\x43\x08\xc3'),                                    # mov QWORD PTR [rbx+0x8],rax; ret
    ({StoreMem : 1},        '\x48\x89\x44\x24\x08\xc3'),                                # mov QWORD PTR [rsp+0x8],rax; ret
    ({LoadAddGadget: 1},    '\x48\x03\x44\x24\x08\xc3'),                                # add rax,QWORD PTR [rsp+0x8]
    ({StoreAddGadget: 1},   '\x48\x01\x43\xf8\xc3'),                                    # add QWORD PTR [rbx-0x8],rax; ret
    ({},                    '\x48\x39\xeb\xc3'),                                        # cmp rbx, rbp; ret
    ({},                    '\x5e'),                                                    # pop rsi
    ({},                    '\x8b\x04\xc5\xc0\x32\x45\x00\xc3'),                        # mov rax,QWORD PTR [rax*8+0x4532c0]
    ({LoadMem : 1, LoadConst : 1}, '\x59\x48\x89\xcb\x48\xc7\xc1\x05\x00\x00\x00\xc3'), # pop rcx; mov rbx,rcx; mov rcx,0x5; ret
  ]

  classifier = GadgetClassifier(logging.DEBUG)
  fail = False
  for (expected_types, code) in tests:
    gadgets = classifier.create_gadgets_from_instructions([x for x in disassembler.disasm(code, 0x400000)]) # Expand the generator
    types = {}

    # For each returned gadget, count the number of each gadget types
    for g in gadgets:
      if type(g) not in types: types[type(g)] = 0
      types[type(g)] += 1

    if types != expected_types: # If we got the wrong number of gagdets for any type, we've failed
      fail = True
      print "\nWrong Types Found.  Expected {}, got {}".format(
        ",".join(["{} {}".format(t.__name__, c) for t,c in expected_types.items()]),
        ",".join(["{} {}".format(t.__name__, c) for t,c in types.items()]))

      print "Gadgets:"
      for g in gadgets:
        print g
      print "\n"

  if fail:
    print "FAILURE!!! One or more incorrectly classified gadgets"
  else:
    print "SUCCESS, all gadgets correctly classified"

