import collections, logging, random, sys
import pyvex, archinfo

from gadget import *
import utils

class GadgetClassifier(object):
  """This class is used to convert a set of instructions that represent a gadget into a Gadget class of the appropriate type"""

  """The number of times to emulate a gadget when classifying it"""
  NUM_VALIDATIONS = 5

  """Registers reported by pyvex that we don't care to look for, per architecture"""
  IGNORED_REGISTERS = collections.defaultdict(list, {
    "X86"   : ['bp', 'cc_dep1', 'cc_dep2', 'cc_ndep', 'cc_op', 'cs', 'd', 'ds', 'es', 'fc3210', 'fpround', 'fpu_regs',
               'fpu_t0', 'fpu_t1', 'fpu_t2', 'fpu_t3', 'fpu_t4', 'fpu_t5', 'fpu_t6', 'fpu_t7', 'fpu_tags', 'fs', 'ftop', 'gdt',
               'gs', 'id', 'ldt', 'mm0', 'mm1', 'mm2', 'mm3', 'mm4', 'mm5', 'mm6', 'mm7', 'ss', 'sseround', 'st0', 'st1',
               'st2', 'st3', 'st4', 'st5', 'st6', 'st7', 'xmm0', 'xmm1', 'xmm2', 'xmm3', 'xmm4', 'xmm5', 'xmm6', 'xmm7'],
    "AMD64" : [ "cc_dep1", "cc_dep2", "cc_ndep", "cc_op", "d", "fpround", "fs", "sseround"  ]
  })

  def __init__(self, arch, log_level = logging.WARNING):
    logging.basicConfig(format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    self.arch = arch()
    self.logger = logging.getLogger(self.__class__.__name__)
    self.logger.setLevel(log_level)

    # A couple helper fields
    self.sp = self.arch.registers['sp'][0]
    self.ip = self.arch.registers['ip'][0]

  def is_ignored_register(self, register):
    return self.arch.translate_register_name(register) in self.IGNORED_REGISTERS[self.arch.name]

  def get_irsb(self, code, address):
    irsb = None
    try:
      irsb = pyvex.IRSB(code, address, self.arch)
    except:
      pass
    return irsb

  def get_stack_offset(self, state):
    stack_offset = 0
    if self.sp in state.out_regs and self.sp in state.in_regs: 
      stack_offset = state.out_regs[self.sp] - state.in_regs[self.sp]
    if stack_offset < 0:
      stack_offset = None
    return stack_offset

  def get_new_ip_from_potential_gadget(self, possible_types):
    """Finds the offset of rip in the stack, or whether it was set via a register for a list of potential gadgets""" 
    ip_in_stack_offset = ip_from_reg = None
    for (gadget_type, inputs, output, params, clobber) in possible_types:
      if gadget_type == LoadMem and output == self.ip and inputs[0] == self.sp:
        ip_in_stack_offset = params[0]
      if gadget_type == MoveReg and output == self.ip:
        ip_from_reg = inputs[0]
    return ip_in_stack_offset, ip_from_reg

  def calculate_clobber_registers(self, state, gadget_type, output):
    clobber = []
    for oreg in state.out_regs.keys():
      if oreg != output and oreg != self.ip and oreg != self.sp and not self.is_ignored_register(oreg):
        clobber.append(oreg)
    return clobber

  def create_gadgets_from_instructions(self, code, address):
    irsb = self.get_irsb(code, address)
    if irsb == None:
      return []

    possible_types = None
    stack_offsets = set()
    for i in range(self.NUM_VALIDATIONS):
      evaluator = PyvexEvaluator(self.arch)
      if not evaluator.emulate_statements(irsb.statements):
        return []
      state = evaluator.get_state()

      # Calculate the possible types
      possible_types_this_round = self.check_execution_for_gadget_types(state)

      # Get the stack offset and clobbers register set
      stack_offsets.add(self.get_stack_offset(state))

      if possible_types == None: # For the first round, just make sure that each type only accesses acceptable regions of memory
        possible_types = []
        for possible_type_this_round in possible_types_this_round:
          if self.all_acceptable_memory_accesses(state, possible_type_this_round):
            possible_types.append(possible_type_this_round)
      else: # For each round, only keep the potential gadgets that are in each round
        new_possible_types = []
        for possible_type_this_round in possible_types_this_round:
          for possible_type in possible_types:
            if possible_type_this_round == possible_type:
              new_possible_types.append(possible_type)
        possible_types = new_possible_types

    # Get the new IP and SP values
    ip_in_stack_offset, ip_from_reg = self.get_new_ip_from_potential_gadget(possible_types)
    stack_offset = stack_offsets.pop()
    if len(stack_offsets) != 0 or stack_offset == None: # We require a constant non-negative change in the stack size
      return []

    gadgets = []
    for (gadget_type, inputs, output, params, clobber) in possible_types:
      if (
        # Ignore the LoadMem gadget for the IP register
        (output == self.ip and gadget_type != Jump)

        # Except for Jump, all the gadgets must load rip from the stack
        or ((ip_in_stack_offset == None and gadget_type != Jump) and not (ip_from_reg != None and gadget_type == LoadMem))

        # If the stack doesn't get adjusted
        or (ip_in_stack_offset != None and ((gadget_type == LoadMem and params[0] > stack_offset) or ip_in_stack_offset > stack_offset))

        # We don't care about finding gadgets that set the flags
        or self.is_ignored_register(output)

        # If it's a LoadMem that results in a jmp to the load register, thus we can't actually load any value we want
        or (gadget_type == LoadMem and params[0] == ip_in_stack_offset and inputs[0] == self.sp)
        ):
        continue

      # Convert a LoadMem gadget into a LoadMemJump if the IP is set from a register
      if ip_from_reg != None and gadget_type == LoadMem:
        gadget_type = LoadMemJump
        inputs.append(ip_from_reg)

      gadget = gadget_type(self.arch, address, inputs, output, params, clobber, stack_offset, ip_in_stack_offset)
      if gadget != None and gadget.validate():
        self.logger.debug("Found gadget: %s", str(gadget))
        gadgets.append(gadget)

    return gadgets

  def all_acceptable_memory_accesses(self, state, possible_type):
    (gadget_type, inputs, output, params, clobber) = possible_type

    # Always allow the LoadMem gadget for loading IP from the Stack
    if gadget_type == LoadMem and output == self.ip and inputs[0] == self.sp:
      return True

    for mem_address, mem_value in state.in_mem.items():
      good_mem_access = False
      if not (
          # Allow the LoadMem's read
          (gadget_type == LoadMem and mem_address == state.in_regs[inputs[0]] + params[0] and state.out_regs[output] == mem_value)

          # Allow the ArithmeticLoad's read
          or (issubclass(gadget_type, ArithmeticLoad) and mem_address == state.in_regs[inputs[0]] + params[0])

          # Allow the ArithmeticStore's read
          or (issubclass(gadget_type, ArithmeticStore) and mem_address == state.in_regs[inputs[0]] + params[0])

          # Allow loads from the SP register (i.e. pop)
          or (self.sp in state.in_regs and abs(mem_address - state.in_regs[self.sp]) < 0x1000)
      ):
        return False

    for mem_address, mem_value in state.out_mem.items():
      if not (
        # Allow the StoreMem's write
        (gadget_type == StoreMem and mem_address == state.in_regs[inputs[0]] + params[0] and mem_value == state.in_regs[inputs[1]])

        # Allow the ArithmeticStore's write
        or (issubclass(gadget_type, ArithmeticStore) and mem_address == state.in_regs[inputs[0]] + params[0])
      ):
        return False

    return True

  def check_execution_for_gadget_types(self, state):
    """Given the results of an emulation of a set of instructions, check the results to determine any potential gadget types and
      the associated inputs, outputs, and parameters.  This is done by checking the results to determine any of the
      preconditions that the gadget follows for this execution.  This method returns a list of the format
      (Gadget Type, list of inputs, output, list of parameters).  Note the returned potential gadgets are a superset of the 
      actual gadgets, i.e. some of the returned ones are merely coincidences in the emulation, and not true gadgets."""
    possible_types = []
 
    for oreg, ovalue in state.out_regs.items():
      # Check for LOAD_CONST (it'll get filtered between the multiple rounds)
      possible_types.append((LoadConst, [], oreg, [ovalue]))

      for ireg, ivalue in state.in_regs.items():
        # Check for MOV_REG
        if ovalue == ivalue:
          possible_types.append((MoveReg, [ireg], oreg, []))

        # Check for JUMP_REG
        if oreg == self.arch.registers['ip'][0]:
          possible_types.append((Jump, [ireg], oreg, [ovalue - ivalue]))

        # Check for ARITHMETIC
        if ireg != oreg: # add rbx, rax (where rbx is dst/operand 1 and rax is operand 2)
          continue

        for ireg2, ivalue2 in state.in_regs.items():
          if ovalue == ivalue + ivalue2:
            possible_types.append((AddGadget, [ireg, ireg2], oreg, []))
          if ovalue == ivalue - ivalue2:
            possible_types.append((SubGadget, [ireg, ireg2], oreg, []))
          if ovalue == ivalue * ivalue2:
            possible_types.append((MulGadget, [ireg, ireg2], oreg, []))
          if ovalue == ivalue & ivalue2 and ireg != ireg2:
            possible_types.append((AndGadget, [ireg, ireg2], oreg, []))
          if ovalue == ivalue | ivalue2 and ireg != ireg2:
            possible_types.append((OrGadget, [ireg, ireg2], oreg, []))
          if ovalue == ivalue ^ ivalue2:
            possible_types.append((XorGadget, [ireg, ireg2], oreg, []))

      for address, value_at_address in state.in_mem.items():
        # Check for ARITHMETIC_LOAD
        for ireg, ivalue in state.in_regs.items():
          for addr_reg, addr_reg_value in state.in_regs.items():
            if ovalue == ivalue + value_at_address:
              possible_types.append((LoadAddGadget, [ireg], oreg, [address - addr_reg_value]))
            if ovalue == ivalue - value_at_address:
              possible_types.append((LoadSubGadget, [ireg], oreg, [address - addr_reg_value]))
            if ovalue == ivalue * value_at_address:
              possible_types.append((LoadMulGadget, [ireg], oreg, [address - addr_reg_value]))
            if ovalue == ivalue & value_at_address: 
              possible_types.append((LoadAndGadget, [ireg], oreg, [address - addr_reg_value]))
            if ovalue == ivalue | value_at_address:
              possible_types.append((LoadOrGadget, [ireg], oreg, [address - addr_reg_value]))
            if ovalue == ivalue ^ value_at_address:
              possible_types.append((LoadXorGadget, [ireg], oreg, [address - addr_reg_value]))

        # Check for LOAD_MEM
        if ovalue == value_at_address:
          for ireg, ivalue in state.in_regs.items():
            possible_types.append((LoadMem, [ireg], oreg, [address - ivalue]))

    for address, value in state.out_mem.items():
      for ireg, ivalue in state.in_regs.items():
        # Check for STORE_MEM
        if value == ivalue:
          for addr_reg, addr_reg_value in state.in_regs.items():
            possible_types.append((StoreMem, [addr_reg, ireg], None, [address - addr_reg_value]))

        # Check for ARITHMETIC_STORE
        initial_memory_value = None
        if not address in state.in_mem.keys():
          continue

        initial_memory_value = state.in_mem[address]

        for addr_reg, addr_reg_value in state.in_regs.items():
          if value == initial_memory_value + ivalue:
            possible_types.append((StoreAddGadget, [addr_reg, ireg], None, [address - addr_reg_value]))
          if value == initial_memory_value - ivalue:
            possible_types.append((StoreSubGadget, [addr_reg, ireg], None, [address - addr_reg_value]))
          if value == initial_memory_value * ivalue:
            possible_types.append((StoreMulGadget, [addr_reg, ireg], None, [address - addr_reg_value]))
          if value == initial_memory_value & ivalue:
            possible_types.append((StoreAndGadget, [addr_reg, ireg], None, [address - addr_reg_value]))
          if value == initial_memory_value | ivalue:
            possible_types.append((StoreOrGadget, [addr_reg, ireg], None, [address - addr_reg_value]))
          if value == initial_memory_value ^ ivalue:
            possible_types.append((StoreXorGadget, [addr_reg, ireg], None, [address - addr_reg_value]))

    # Add the clobber set to the possible types
    possible_types_with_clobber = []
    for (gadget_type, inputs, output, params) in possible_types:
      clobber = self.calculate_clobber_registers(state, gadget_type, output)
      possible_types_with_clobber.append((gadget_type, inputs, output, params, clobber))
    return possible_types_with_clobber

class EvaluateState(object):
  def __init__(self, arch):
    self.arch = arch
    self.in_regs = collections.defaultdict(lambda: random.randint(0, 2 ** (arch.bits - 2)), {})
    self.in_mem  = collections.defaultdict(lambda: random.randint(0, 2 ** (arch.bits - 2)), {})
    self.out_regs = {}
    self.out_mem = {}
    self.tmps = {}

  def __str__(self):
    ireg = "IR(" + ", ".join(["{}=0x{:x}".format(
      self.arch.translate_register_name(reg), value) for reg, value in self.in_regs.items()]) + ")"
    oreg = "OR(" + ", ".join(["{}=0x{:x}".format(
      self.arch.translate_register_name(reg), value) for reg, value in self.out_regs.items()]) + ")"
    imem = "IM(" + ", ".join(["0x{:x}=0x{:x}".format(addr, value) for addr, value in self.in_mem.items()]) + ")"
    omem = "OM(" + ", ".join(["0x{:x}=0x{:x}".format(addr, value) for addr, value in self.out_mem.items()]) + ")"
    return "State({}{}{}{})".format(ireg,oreg,imem,omem)

  def set_tmp(self, tmp, value):
    self.tmps[tmp] = value

  def get_tmp(self, tmp, size):
    return utils.mask(self.tmps[tmp], size)

  def set_reg(self, reg, value):
    self.out_regs[reg] = value

  def get_reg(self, reg, size):
    if reg in self.out_regs:
      val = utils.mask(self.out_regs[reg], size)
      return utils.mask(self.out_regs[reg], size)
    return utils.mask(self.in_regs[reg], size)

  def set_mem(self, address, value):
    self.out_mem[address] = value

  def get_mem(self, address, size):
    if address in self.out_mem:
      return utils.mask(self.out_mem[address], size)
    return utils.mask(self.in_mem[address], size)

class PyvexEvaluator(object):

  def __init__(self, arch):
    self.arch = arch
    self.state = EvaluateState(arch)

  def emulate_statements(self, statements):
    for stmt in statements:
      try:
        if hasattr(self, stmt.tag):
          getattr(self, stmt.tag)(stmt)
        else:
          self.unknown_statement(stmt)
      except:
          return False
    return True

  def get_state(self):
    return self.state

  # Statement Emulators

  def Ist_WrTmp(self, stmt):
    self.state.set_tmp(stmt.tmp, getattr(self, stmt.data.tag)(stmt.data))

  def Ist_Put(self, stmt):
    self.state.set_reg(stmt.offset, getattr(self, stmt.data.tag)(stmt.data))

  def Ist_Store(self, stmt):
    address = getattr(self, stmt.addr.tag)(stmt.addr)
    value = getattr(self, stmt.data.tag)(stmt.data)
    self.state.set_mem(address, value)

  def Ist_IMark(self, stmt): pass
  def Ist_NoOp(self, stmt):  pass
  def Ist_AbiHint(self, stmt): pass
  def Ist_Exit(self, stmt): pass

  def unknown_statement(self, stmt):
    """Raises a RuntimeError. Used to signify that the current statement is one we don't know how to emulate"""
    raise RuntimeError("Unknown statement: {}".format(stmt.tag))

  # Expression Emulators

  def Iex_Get(self, expr):
    return self.state.get_reg(expr.offset, expr.result_size)
    
  def Iex_RdTmp(self, argument):
    return self.state.get_tmp(argument.tmp, argument.result_size)

  def Iex_Load(self, expr):
    address = getattr(self, expr.addr.tag)(expr.addr)
    return self.state.get_mem(address, expr.result_size)
    
  def Iex_Const(self, expr):
    return getattr(self, expr.con.tag)(expr.con)

  def Ico_U8(self, constant):
    return utils.mask(constant.value, 8)

  def Ico_U32(self, constant):
    return utils.mask(constant.value, 32)

  def Ico_U64(self, constant):
    return utils.mask(constant.value, 64)

  def Iex_Unop(self, expr):
    argument = getattr(self, expr.args[0].tag)(expr.args[0])
    return getattr(self, expr.op)(argument)

  def Iop_64to32(self, argument):
    return utils.mask(argument, 32)

  def Iop_32Uto64(self, argument):
    return utils.mask(argument)

  def Iop_8Uto64(self, argument):
    return utils.mask(argument)

  def Iop_32Sto64(self, argument):
    if argument >= 0:
      return argument
    else:
      return (2 ** 64) + argument

  def Iex_Binop(self, expr):
    left = getattr(self, expr.args[0].tag)(expr.args[0])
    right = getattr(self, expr.args[1].tag)(expr.args[1])
    return getattr(self, expr.op)(left, right)

  def Iop_And64(self, left, right): return left & right
  def Iop_And32(self, left, right): return left & right

  def Iop_Xor64(self, left, right): return left ^ right
  def Iop_Xor32(self, left, right): return left ^ right

  def Iop_Add64(self, left, right): return utils.mask(left + right)
  def Iop_Add32(self, left, right): return utils.mask(left + right, 32)
  def Iop_Add8(self, left, right):  return utils.mask(left + right, 8)

  def Iop_Sub64(self, left, right): return utils.mask(left - right)
  def Iop_Sub32(self, left, right): return utils.mask(left - right, 32)

  def Iop_Shl64(self, left, right): return utils.mask(left << right)
  def Iop_Shl32(self, left, right): return utils.mask(left << right, 32)

  def Iop_CmpEQ64(self, left, right): return 1 if utils.mask(left, 64) == utils.mask(right, 64) else 0
  def Iop_CmpEQ32(self, left, right): return 1 if utils.mask(left, 32) == utils.mask(right, 32) else 0

  def Iop_CmpNE64(self, left, right): return 1 if utils.mask(left, 64) != utils.mask(right, 64) else 0
  def Iop_CmpNE32(self, left, right): return 1 if utils.mask(left, 32) != utils.mask(right, 32) else 0

if __name__ == "__main__":
  # A simple set of tests to ensure we can correctly classify some example gadgets
  tests = {
    archinfo.ArchAMD64 : [
      ({Jump : 1},            '\xff\xe0'),                                                # jmp rax
      ({MoveReg : 2},         '\x48\x93\xc3'),                                            # xchg rbx, rax; ret
      ({MoveReg : 1},         '\x48\x89\xcb\xc3'),                                        # mov rbx,rcx; ret
      ({LoadConst : 1},       '\x48\xbb\xff\xee\xdd\xcc\xbb\xaa\x99\x88\xc3'),            # movabs rbx,0x8899aabbccddeeff; ret
      ({AddGadget : 1},       '\x48\x01\xc3\xc3'),                                        # add rbx, rax; reg
      ({LoadMem : 1},         '\x48\x8b\x43\x08\xc3'),                                    # mov rax,QWORD PTR [rbx+0x8]; ret
      ({LoadMem : 1},         '\x48\x8b\x07\xc3'),                                        # mov rax,QWORD PTR [rdi]; ret
      ({StoreMem : 1},        '\x48\x89\x03\xc3'),                                        # mov QWORD PTR [rbx],rax; ret
      ({StoreMem : 1},        '\x48\x89\x43\x08\xc3'),                                    # mov QWORD PTR [rbx+0x8],rax; ret
      ({StoreMem : 1},        '\x48\x89\x44\x24\x08\xc3'),                                # mov QWORD PTR [rsp+0x8],rax; ret
      ({LoadAddGadget: 1},    '\x48\x03\x44\x24\x08\xc3'),                                # add rax,QWORD PTR [rsp+0x8]
      ({StoreAddGadget: 1},   '\x48\x01\x43\xf8\xc3'),                                    # add QWORD PTR [rbx-0x8],rax; ret
      ({},                    '\x48\x39\xeb\xc3'),                                        # cmp rbx, rbp; ret
      ({},                    '\x5e'),                                                    # pop rsi
      ({},                    '\x8b\x04\xc5\xc0\x32\x45\x00\xc3'),                        # mov rax,QWORD PTR [rax*8+0x4532c0]
      ({LoadMem : 1, LoadConst : 1}, '\x59\x48\x89\xcb\x48\xc7\xc1\x05\x00\x00\x00\xc3'), # pop rcx; mov rbx,rcx; mov rcx,0x5; ret
      ({},                    '\x48\x8b\x85\xf0\xfd\xff\xff\x48\x83\xc0'),
#      ({LoadMemJump : 1, },   '\x5a\xfc\xff\xd0'),                                        # pop rdx, cld, call rax
    ],
    archinfo.ArchMIPS64 : [
      ({LoadMem : 1},
        '\x8f\xbf\x00\x10' + # lw ra,16(sp)
        '\x8f\xb0\x00\x08' + # lw s0,8(sp)
        '\x03\xe0\x00\x08' + # jr ra
        '\x00\x00\x00\x00')  # nop
    ],
    archinfo.ArchPPC32 : [
      ({LoadMem : 1},
        '\x08\x00\xe1\x83' + # lwz r31,8(r1)
        '\x04\x00\x01\x80' + # lwz r0,4(r1)
        '\xa6\x03\x08\x7c' + # mtlr r0
        '\x20\x00\x80\x4e')  # blr
    ],
    archinfo.ArchARM : [
      ({LoadMem     : 1}, '\x08\x80\xbd\xe8'),                 # pop {r3, pc}
      ({MoveReg     : 1}, '\x02\x00\xa0\xe1\x04\xf0\x9d\xe4'), # mov r0, r2; pop {pc}
      ({LoadMem     : 7}, '\xf0\x87\xbd\xe8'),                 # pop {r4, r5, r6, r7, r8, r9, sl, pc}
      ({LoadMem     : 2}, '\x04\xe0\x9d\xe5\x08\xd0\x8d\xe2'   # ldr lr, [sp, #4]; add sp, sp, #8
                        + '\x0c\x00\xbd\xe8\x1e\xff\x2f\xe1'), # pop {r2, r3}; bx lr
      ({LoadMemJump : 6, Jump : 1},
                          '\x1f\x40\xbd\xe8\x1c\xff\x2f\xe1'), # pop {r0, r1, r2, r3, r4, lr}; bx r12
      ({LoadMemJump : 1, Jump : 1},
                          '\x04\xe0\x9d\xe4\x13\xff\x2f\xe1'), # pop {lr}; bx r3
    ]
  }
  import sys
  if len(sys.argv) > 1:
    arches = { "AMD64" : archinfo.ArchAMD64, "MIPS" : archinfo.ArchMIPS64, "PPC" : archinfo.ArchPPC32, "ARM" : archinfo.ArchARM}
    arch = arches[sys.argv[1].upper()]
    tests = { arch : tests[arch] }
    if len(sys.argv) > 2:
      tests = { arch : [tests[arch][int(sys.argv[2])]] }

  fail = False
  for arch, arch_tests in tests.items():
    print "\n{} Tests:".format(arch.name)

    classifier = GadgetClassifier(arch, logging.DEBUG)
    for (expected_types, code) in arch_tests:
      gadgets = classifier.create_gadgets_from_instructions(code, 0x40000)
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
    print "\nFAILURE!!! One or more incorrectly classified gadgets"
  else:
    print "\nSUCCESS, all gadgets correctly classified"

