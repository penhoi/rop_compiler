import collections, logging, random, sys, traceback
import pyvex, archinfo
from bitmap import BitMap
from gadget import *
import utils, extra_archinfo, validator

class GadgetClassifier(object):
    """This class is used to convert a set of instructions that represent a gadget into a Gadget class of the appropriate type"""

    """The number of times to emulate a gadget when classifying it"""
    NUM_EMULATIONS = 3

    """The maximum size in bytes of a gadget to look for"""
    MAX_GADGET_SIZE_MAP = { "X86" : 64, 'AMD64' : 64, 'MIPS64' : 36, 'MIPS32' : 36, 'PPC32' : 32, 'PPC64' : 32, 'ARM' : 20,
    'ARMEL' : 20 }


    def __init__(self, arch, code, base_address, validate_gadgets=False, log_level=logging.WARNING):
        logging.basicConfig(format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
        self.arch = arch
        self.validate_gadgets = validate_gadgets
        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.setLevel(log_level)

        #code & base_address
        self.code = code
        self.base_address = base_address
        self.code_length = len(self.code)
        self.black_list = BitMap(self.code_length)
        self.white_list = BitMap(self.code_length)

        # A couple helper fields
        self.sp = self.arch.registers['sp'][0]
        self.ip = self.arch.registers['ip'][0]

        #Used only by get_irsbs
        self.MAX_GADGET_SIZE = self.MAX_GADGET_SIZE_MAP[self.arch.name]

        self.jcc_branches = {}    #Address of all JCC instruction
        self.jcc_blks = []        #Super blocks ending with a JCC instruction

    def is_ignored_register(self, register):
        return self.arch.translate_register_name(register) in extra_archinfo.IGNORED_REGISTERS[self.arch.name]

    def irsb_ends_with_constant_pc(self, irsb):
        """A really bad hack to try to detect if the pc register gets set by the IRSB to a non-constant value (i.e. a jump/ret)"""
        for stmt in irsb.statements:
            # if the statement is a PUT that sets the pc register, and it's a non-constant value
            if stmt.tag == 'Ist_Put' and stmt.offset == self.arch.registers['pc'][0] and stmt.data.tag != 'Iex_Const':
                return False
        return True

    def get_irsbs(self, address):
        """
        Some details about the information returned by IRSB
        1. jcc  & Ijk_Boring  & direct_next:True, const_jumptarget: set([0x40000, 0x40009])
        2. call esi & Ijk_Call  & direct_next:Fase, const_jumptarget: set([])
        3. ret  & Ijk_Ret   & direct_next:Fase, const_jumptarget: set([])
        4. jmp esi  & Ijk_Boring  & direct_next:Fase, const_jumptarget: set([])
        5. jmp local  & Ijk_Boring  & direct_next:True, const_jumptarget: set([0x40000])
        6. call local   & Ijk_Call  & direct_next:True, const_jumptarget: set([0x40000])
        7. pop edi  & Ijk_NoDecode  & direct_next:False, const_jumptarget: set([])
        8. 0xff & Ijk_NoDecode  & direct_next:False, const_jumptarget: set([])
        """
        if address < self.base_address:
            return []

        irsbs = []
        code_address = address
        while code_address <= self.base_address + self.code_length - self.arch.instruction_alignment:
            try:
                oft = code_address - self.base_address
                code = self.code[oft:oft+self.MAX_GADGET_SIZE]
                irsb = pyvex.IRSB(code, code_address, self.arch, opt_level = 0)
                irsbs.append(irsb)
            except: # If decoding fails, we can't use this gadget
                #traceback.print_exc()
                return [] # So just return an empty list

            if (self.arch.name not in extra_archinfo.ENDS_EARLY_ARCHS
                or irsb.jumpkind != 'Ijk_Boring'
                or not self.irsb_ends_with_constant_pc(irsb)):
                break

            # Find the last address that was translated (For some architectures, pyvex stops before the end of a block)
            last_addr = None
            for stmt in irsb.statements:
                if stmt.tag == 'Ist_IMark':
                    last_addr = stmt.addr

            # If we couldn't get any statements from the instructions, there was a problem.
            if last_addr == None:    # So just return an empty list
                return []

            # And move the code address forward to the next untranslated instruction
            code_address = last_addr + self.arch.instruction_alignment

        return irsbs

    def get_stack_offset(self, state):
        stack_offset_without_stack_switch = 0
        stack_offset_with_stack_switch = None   #the maximum offset ever touched

        if self.sp in state.out_regs:
            if self.sp not in state.in_regs:    #Only when RegStackSwitch
                stack_offset_without_stack_switch = None
                stack_offset_with_stack_switch = self.arch.bytes
            else:
                stack_offset_without_stack_switch = state.out_regs[self.sp] - state.in_regs[self.sp]
                #explicitly modify SP, acceptable only there are stackswitch gadgets
                #allow call *%eax and call *%(eax)
                if stack_offset_without_stack_switch % self.arch.bytes != 0:
                    stack_offset_without_stack_switch = None

                addrs = state.in_mem.keys() + state.out_mem.keys()
                stack_offset_with_stack_switch = 0
                for addr in addrs:
                    delta = addr - state.in_regs[self.sp]
                    if abs(stack_offset_with_stack_switch) < abs(delta) < 0xFF:
                        stack_offset_with_stack_switch = delta

        return stack_offset_without_stack_switch, stack_offset_with_stack_switch

    def get_new_ip_from_potential_gadget(self, possible_types):
        """Finds the offset of rip in the stack, or whether it was set via a register for a list of potential gadgets"""
        ip_in_stack_offset = ip_from_reg = None
        ip_from_mem = False
        for (gadget_type, inputs, _outputs, _clobbers, params) in possible_types:
            if issubclass(gadget_type, MemJump):
                ip_from_mem = True
            elif issubclass(gadget_type, Jump):
                ip_from_reg = inputs[0]
            elif gadget_type == RetGadget:
                ip_in_stack_offset = params[0]
            elif gadget_type in [RegStackSwitch, MemStackSwitch]:
                ip_in_stack_offset = params[0]

        return ip_in_stack_offset, ip_from_reg, ip_from_mem

    def calculate_clobber_registers(self, state, gadget_type, outputs):
        clobbers = []
        for oreg in state.out_regs.keys():
            if oreg not in outputs and oreg != self.ip and oreg != self.sp and not self.is_ignored_register(oreg):
                clobbers.append(oreg)
        return clobbers

    def all_acceptable_memory_accesses(self, state, possible_type):
        (gadget_type, inputs, _outputs, _clobbers, params) = possible_type

        if (gadget_type is Jump1):
            inSP = state.in_regs[self.sp] if self.sp in state.in_regs else 0
            outSP = state.out_regs[self.sp] if self.sp in state.out_regs else 0
            minSP = min(inSP, outSP)
            maxSP = max(inSP, outSP)
            for mem_address, _mem_value in state.in_mem.items():
                if not (minSP <= mem_address <= maxSP):
                    return False
            for mem_address, _mem_value in state.out_mem.items():
                if not (minSP <= mem_address <= maxSP):
                    return False

        elif (gadget_type is Jump2):
            if not (len (state.in_mem) == 0 and len (state.out_mem) == 1):
                return False
            oldSP = state.in_regs[self.sp]
            for mem_address, _mem_value in state.out_mem.items():
                if abs(mem_address - oldSP) != 1 * self.arch.bytes:
                    return False

        elif (gadget_type is RegFunCall):
            inSP = state.in_regs[self.sp] if self.sp in state.in_regs else 0
            outSP = state.out_regs[self.sp] if self.sp in state.out_regs else 0
            minSP = min(inSP, outSP)
            maxSP = max(inSP, outSP)
            for mem_address, _mem_value in state.in_mem.items():
                if not (minSP <= mem_address <= maxSP):
                    return False
            for mem_address, _mem_value in state.out_mem.items():
                if not (minSP <= mem_address <= maxSP):
                    return False

        elif (gadget_type is MemFunCall):
            inSP = state.in_regs[self.sp] if self.sp in state.in_regs else 0
            outSP = state.out_regs[self.sp] if self.sp in state.out_regs else 0
            minSP = min(inSP, outSP)
            maxSP = max(inSP, outSP)
            for mem_address, _mem_value in state.in_mem.items():
                if not ((minSP <= mem_address <= maxSP) or (mem_address == state.in_regs[inputs[0]] + params[0])):
                    return False
            for mem_address, _mem_value in state.out_mem.items():
                if not (minSP <= mem_address <= maxSP):
                    return False

        elif (gadget_type is MemJump):
            if self.sp in state.out_regs and self.sp not in state.in_regs:
                return False
            inSP = state.in_regs[self.sp] if self.sp in state.in_regs else 0
            outSP = state.out_regs[self.sp] if self.sp in state.out_regs else 0
            minSP = min(inSP, outSP)
            maxSP = max(inSP, outSP)
            for mem_address, _mem_value in state.in_mem.items():
                if not ((minSP <= mem_address <= maxSP) or (mem_address == state.in_regs[inputs[0]] + params[0])):
                    return False
            for mem_address, _mem_value in state.out_mem.items():
                if not (minSP <= mem_address <= maxSP):
                    return False

        elif (gadget_type is RetGadget):
            return True;

        elif (gadget_type in [MoveReg, LoadConst, Arithmetic, ArithmeticConst, LoadMultiple]):
            if len (state.in_mem) < 1:    #ended with a RET instruction
                return False
            inSP = state.in_regs[self.sp] if self.sp in state.in_regs else 0
            outSP = state.out_regs[self.sp] if self.sp in state.out_regs else 0
            minSP = min(inSP, outSP)
            maxSP = max(inSP, outSP)
            for mem_address, _mem_value in state.in_mem.items():
                if not (minSP <= mem_address <= maxSP):
                    return False
            for mem_address, _mem_value in state.out_mem.items():
                if not (minSP <= mem_address <= maxSP):
                    return False

        elif (gadget_type in [LoadMem, ArithmeticLoad]):
            if len (state.in_mem) < 1:
                return False
            inSP = state.in_regs[self.sp] if self.sp in state.in_regs else 0
            outSP = state.out_regs[self.sp] if self.sp in state.out_regs else 0
            minSP = min(inSP, outSP)
            maxSP = max(inSP, outSP)
            for mem_address, _mem_value in state.in_mem.items():
                if not ((minSP <= mem_address <= maxSP) or (mem_address == state.in_regs[inputs[0]] + params[0])):
                    return False
            for mem_address, _mem_value in state.out_mem.items():
                if not (minSP <= mem_address <= maxSP):
                    return False

        elif (gadget_type is StoreMem):
            if len (state.out_mem) < 1:
                return False
            inSP = state.in_regs[self.sp] if self.sp in state.in_regs else 0
            outSP = state.out_regs[self.sp] if self.sp in state.out_regs else 0
            minSP = min(inSP, outSP)
            maxSP = max(inSP, outSP)
            for mem_address, _mem_value in state.in_mem.items():
                if not (minSP <= mem_address <= maxSP):
                    return False
            for mem_address, _mem_value in state.out_mem.items():
                if not ((minSP <= mem_address <= maxSP) or (mem_address == state.in_regs[inputs[0]] + params[0])):
                    return False

        elif (gadget_type is ArithmeticStore):
            if len (state.in_mem) < 1 or len (state.out_mem) < 1:
                return False
            inSP = state.in_regs[self.sp] if self.sp in state.in_regs else 0
            outSP = state.out_regs[self.sp] if self.sp in state.out_regs else 0
            minSP = min(inSP, outSP)
            maxSP = max(inSP, outSP)
            for mem_address, _mem_value in state.in_mem.items():
                if not ((minSP <= mem_address <= maxSP) or (mem_address == state.in_regs[inputs[0]] + params[0])):
                    return False
            for mem_address, _mem_value in state.out_mem.items():
                if not ((minSP <= mem_address <= maxSP) or (mem_address == state.in_regs[inputs[0]] + params[0])):
                    return False

        elif (gadget_type is RegStackSwitch):
            oldSP = state.in_regs[self.sp] if self.sp in state.in_regs else 0
            newSP = state.out_regs[self.sp] if self.sp in state.out_regs else 0
            for mem_address, _mem_value in state.in_mem.items():
                if not ((abs(mem_address - oldSP) < 0x1000) or (abs(mem_address - newSP) < 0x1000)):
                    return False
            for mem_address, _mem_value in state.out_mem.items():
                if not ((abs(mem_address - oldSP) < 0x1000) or (abs(mem_address - newSP) < 0x1000)):
                    return False

        elif (gadget_type is MemStackSwitch):
            oldSP = state.in_regs[self.sp] if self.sp in state.in_regs else 0
            newSP = state.out_regs[self.sp] if self.sp in state.out_regs else 0
            for mem_address, _mem_value in state.in_mem.items():
                if not ((abs(mem_address - oldSP) < 0x1000) or (abs(mem_address - newSP) < 0x1000) or
                        (abs(mem_address - state.in_regs[inputs[0]]) < 0x1000)):
                    return False
            for mem_address, _mem_value in state.out_mem.items():
                if not ((abs(mem_address - oldSP) < 0x1000) or (abs(mem_address - newSP) < 0x1000)):
                    return False

        return True

    def _check_jump_gadget_types(self, state, newIP, deltaSP):
        """
        All gadgets ending with indirect call and jump, or equivalent code such as push;ret
        """
        possible_types = []
        for ireg, ivalue in state.in_regs.items():
            if ireg == self.sp:
                continue
            offset = newIP - ivalue
            if deltaSP == 0 * self.arch.bytes:
                possible_types.append((Jump2, [ireg], [self.ip], [offset]))
            if deltaSP >= 0 * self.arch.bytes:
                possible_types.append((Jump1, [ireg], [self.ip], [offset]))
            else:
                possible_types.append((RegFunCall, [ireg], [self.ip], [offset]))

        #end for
        for address, value_at_address in state.in_mem.items():
            if newIP != value_at_address:
                continue
            for ireg, ivalue in state.in_regs.items():
                if ireg == self.sp:
                    continue
                offset = address - ivalue
                if deltaSP >= 0 * self.arch.bytes:
                    possible_types.append((MemJump, [ireg], [self.ip], [offset]))
                else:
                    possible_types.append((MemFunCall, [ireg], [self.ip], [offset]))
        return possible_types

    def _check_stackswitch_gadget_types(self, state, newSP, deltaSP):
        possible_types = []
        for ireg, ivalue in state.in_regs.items():
            if ireg == self.sp:
                #We allow adding a constant to SP register
                if deltaSP % self.arch.bytes == 0 and deltaSP > 1*self.arch.bytes:
                    possible_types.append((AddConstGadget, [ireg], [self.sp], [deltaSP]))
            else:
                offset = newSP - ivalue
                possible_types.append((RegStackSwitch, [ireg], [self.sp], [offset]))
        #end for
        for address, value_at_address in state.in_mem.items():
            if abs(newSP - value_at_address) != 1 * self.arch.bytes:
                continue
            for ireg, ivalue in state.in_regs.items():
                offset = address - ivalue
                possible_types.append((MemStackSwitch, [ireg], [self.sp], [offset]))
        return possible_types

    def _possible_types_with_clobber(self, state, possible_types):
        # Add the clobber set to the possible types
        possible_types_with_clobber = []
        for (gadget_type, inputs, outputs, params) in possible_types:
            if gadget_type == RetGadget:
                clobbers = list(set(state.in_regs.keys() + state.out_regs.keys()) - set([self.sp, self.ip]))
            else:
                clobbers = self.calculate_clobber_registers(state, gadget_type, outputs)
            possible_types_with_clobber.append((gadget_type, inputs, outputs, clobbers, params))
        return possible_types_with_clobber

    def check_execution_for_gadget_types(self, state):
        """Given the results of an emulation of a set of instructions, check the results to determine any potential gadget types and
            the associated inputs, outputs, and parameters.    This is done by checking the results to determine any of the
            preconditions that the gadget follows for this execution.    This method returns a list of the format
            (Gadget Type, list of inputs, output, list of parameters).    Note the returned potential gadgets are a superset of the
            actual gadgets, i.e. some of the returned ones are merely coincidences in the emulation, and not true gadgets."""
        possible_types = []
        all_loaded_regs = {}
        if (self.sp in state.in_regs) and (self.sp in state.out_regs):
            deltaSP = state.out_regs[self.sp] - state.in_regs[self.sp]
        else:
            deltaSP = 0

        if deltaSP % self.arch.bytes != 0:    #acceptable only when there is a stackswitch gadget
            gadgets = self._check_stackswitch_gadget_types(state, state.out_regs[self.sp], deltaSP)
            return self._possible_types_with_clobber(state, gadgets)

        for oreg, ovalue in state.out_regs.items():
            #check for jump variants
            if oreg == self.ip:
                #All gadgets ending with indirect call and jump, or equivalent code such as push;ret
                possible_types += self._check_jump_gadget_types(state, ovalue, deltaSP)
                #return a RetGadget if it is ending a RET instruction
                for address, value_at_address in state.in_mem.items():
                    if ovalue != value_at_address:
                        continue
                    for ireg, ivalue in state.in_regs.items():
                        if ireg != self.sp:
                            continue
                        possible_types.append((RetGadget, [self.sp], [self.ip], [address - ivalue]))

            #StackSwitch gadgets
            elif oreg == self.sp:
                possible_types += self._check_stackswitch_gadget_types(state, state.out_regs[self.sp], deltaSP)

            #check for the others, more execution makes filtering mechanism perfect
            else:
                # Check for LOAD_CONST (it'll get filtered between the multiple rounds)
                if deltaSP > 0 * self.arch.bytes:
                    possible_types.append((LoadConst, [], [oreg], [ovalue]))

                for ireg, ivalue in state.in_regs.items():
                    # Check for MoveReg
                    if ovalue == ivalue and oreg != ireg:
                        possible_types.append((MoveReg, [ireg], [oreg], []))

                    # Check for ArithmeticConst
                    #if ireg != self.sp:
                    if ireg != self.sp and ireg == oreg: #enforced on x86 arch
                        possible_types.append((AddConstGadget, [ireg], [oreg], [ovalue - ivalue]))

                    # Check for Arithmetic
                    if oreg != ireg: #enforced on x86 arch
                        continue
                    for ireg2, ivalue2 in state.in_regs.items():
                        if ireg2 == oreg:
                            continue
                        for gadget_type in [AddGadget, SubGadget, MulGadget, AndGadget, OrGadget, XorGadget]:
                            if ovalue == utils.mask(gadget_type.binop(ivalue, ivalue2), self.arch.bits):
                                possible_types.append((gadget_type, [ireg, ireg2], [oreg], []))

                for address, value_at_address in state.in_mem.items():
                    # Check for LoadMem
                    if ovalue == value_at_address and deltaSP >= 1 * self.arch.bytes:
                        for ireg, ivalue in state.in_regs.items():
                            offset = address - ivalue
                            possible_types.append((LoadMem, [ireg], [oreg], [offset]))

                            # Gather all output registers for the LoadMultiple check
                            if (oreg != self.ip and  # We don't want to include the IP register in the LoadMultiple outputs,
                                    (self.ip not in state.out_regs.keys() or ovalue != state.out_regs[self.ip])):    # Or a register which becomes the IP
                                all_loaded_regs[oreg] = address

                    # Check for ArithmeticLoad
                    for ireg, ivalue in state.in_regs.items():
                        if ireg == self.sp:
                            continue
                        if oreg != ireg: #enforced on x86 arch
                            continue
                        for addr_reg, addr_reg_value in state.in_regs.items():
                            for gadget_type in [LoadAddGadget, LoadSubGadget, LoadMulGadget, LoadAndGadget, LoadOrGadget, LoadXorGadget]:
                                if ovalue == utils.mask(gadget_type.binop(ivalue, value_at_address), self.arch.bits):
                                    possible_types.append((gadget_type, [addr_reg, ireg], [oreg], [address - addr_reg_value]))

        # Check for LoadMultiple
        # Note: we don't bother checking that they're all being loaded via the same register since we later only allow non-LoadMem
        # reads only if they're from the stack pointer
        if len(all_loaded_regs) > 1:

            # Gather all the [address] -> register pairings
            params_to_regs = collections.defaultdict(list, {})
            for oreg, address in all_loaded_regs.items():
                params_to_regs[address].append(oreg)

            # Get all the permutations of registers we can set at once without using the same address twice
            permutations = utils.get_permutations(params_to_regs, params_to_regs.keys())
            for permutation in permutations:
                if len(permutation) > 1:
                    permutation.sort() # sort to make sure they're always in the same order
                    for ireg, ivalue in state.in_regs.items():
                        possible_types.append((LoadMultiple, [ireg], permutation, map(lambda r: all_loaded_regs[r] - ivalue, permutation)))

        for address, value in state.out_mem.items():
            for ireg, ivalue in state.in_regs.items():
                # Check for StoreMem
                if value == ivalue:
                    for addr_reg, addr_reg_value in state.in_regs.items():
                        possible_types.append((StoreMem, [addr_reg, ireg], [], [address - addr_reg_value]))

                # Check for ArithmeticStore
                if not address in state.in_mem.keys():
                    continue

                initial_memory_value = state.in_mem[address]
                for addr_reg, addr_reg_value in state.in_regs.items():
                    if addr_reg == self.sp:
                        continue
                    for gadget_type in [StoreAddGadget, StoreSubGadget, StoreMulGadget, StoreAndGadget, StoreOrGadget, StoreXorGadget]:
                        if value == utils.mask(gadget_type.binop(initial_memory_value, ivalue), self.arch.bits):
                            possible_types.append((gadget_type, [addr_reg, ireg], [], [address - addr_reg_value]))

        # Add the clobber set to the possible types
        return self._possible_types_with_clobber(state, possible_types)

    def _create_gadgets_from_instructions(self, address, irsbs):
        possible_types = None
        stack_offsets = set()
        touched_offsets = set()

        for _i in range(self.NUM_EMULATIONS):
            state = EvaluateState(self.arch)
            evaluator = PyvexEvaluator(state, self.arch)
            if not evaluator.emulate_irsbs(irsbs):
                return []
            state = evaluator.get_state()
            # Calculate the possible types
            possible_types_this_round = self.check_execution_for_gadget_types(state)

            # Get the stack offset and clobbers register set
            offset, maxtouch = self.get_stack_offset(state)
            stack_offsets.add(offset)
            touched_offsets.add(maxtouch)

            # For the first round, just make sure that each type only accesses acceptable regions of memory
            if possible_types == None:
                possible_types = []
                for possible_type_this_round in possible_types_this_round:
                    if self.all_acceptable_memory_accesses(state, possible_type_this_round):
                        possible_types.append(possible_type_this_round)

            else:
                new_possible_types = []
                for possible_type_this_round in possible_types_this_round:
                    if possible_type_this_round in possible_types:
                        new_possible_types.append(possible_type_this_round)
                possible_types = new_possible_types

        # Get the new IP and SP values; ip_from_mem means ip from non-stack memory
        ip_in_stack_offset, ip_from_reg, _ip_from_mem = self.get_new_ip_from_potential_gadget(possible_types)
        stack_offset = stack_offsets.pop()

        # Are there stack switch gadgets?
        if len(stack_offsets) != 0 or (stack_offset is None):
            maxtouch = touched_offsets.pop()
            if len(touched_offsets) != 0 or maxtouch is None:
                return []
            stack_offset = maxtouch
            stackswitch_types = []
            for possible_type_this_round in possible_types:
                if possible_type_this_round[0] in [RegStackSwitch, MemStackSwitch]:
                    stackswitch_types.append(possible_type_this_round)
            possible_types = stackswitch_types

        gadgets = []
        for (gadget_type, inputs, outputs, clobbers, params) in possible_types:
            if (
                # Ignore the LoadMem gadget for the IP register
                (issubclass(gadget_type, Jump) and not (len(inputs) > 0 and len(outputs) > 0 and outputs[0] == self.ip))

                #The IP get instruction address from stack if current gadgets ending with a RET instruction
                or (issubclass(gadget_type, RetGadget) and not (ip_in_stack_offset != None or (ip_from_reg != None and gadget_type == LoadMem)))

                #Further check for AddConstGadget
                or (gadget_type is AddConstGadget and ((outputs[0] == self.sp and params[0] <= (len(clobbers)+1) * self.arch.bytes)))

                #On X86, the destination register is also the first operand
                or (issubclass(gadget_type, Arithmetic) and not (outputs[0] == inputs[0]))

                #The stackswitch gadgets should be simply ended with a RET instruction.
                or (issubclass(gadget_type, StackSwitch) and (len(clobbers) > 1))

                # We don't care about finding gadgets that only set the flags
                or (len(outputs) != 0 and all(map(self.is_ignored_register, outputs)))

            ):
                continue

            if ip_from_reg != None and gadget_type == LoadMem:
                gadget_type = LoadMemJump
                inputs.append(ip_from_reg)

            if gadget_type == RetGadget:
                if (len(inputs) == 1 and inputs[0] == self.sp and
                    len(outputs) == 1 and outputs[0] == self.ip and
                    len(clobbers) == 0 and
                    len(params) == 1 and params[0] == ip_in_stack_offset == 0):
                    gadget_type = NOP
                else:
                    continue

            gadget = gadget_type(self.arch, address, inputs, outputs, clobbers, params, stack_offset, ip_in_stack_offset)
            if gadget != None and self.validate_gadgets:
                gadget_validator = validator.Validator(self.arch)
                if not gadget_validator.validate_gadget(gadget, irsbs):
                    gadget = None

            if gadget != None:
                self.logger.debug("Found gadget: %s", str(gadget))
                gadgets.append(gadget)

        return gadgets


    def _extract_jcc_info(self, irsb, code_address):
        CondAlways = 16
        bvalid = False
        if len(irsb.constants) > 0:
            cond = irsb.constants[-1].value
            bvalid = (type(cond) in [int, long] and cond < CondAlways)
        if not bvalid:
            return

        jcc_addr = None
        for stmt in irsb.statements[::-1]:
            if stmt.tag == 'Ist_IMark':
                jcc_addr = stmt.addr
                break
        if jcc_addr != None:
            if jcc_addr not in self.jcc_branches:
                (br1, br2) = list(irsb.constant_jump_targets)
                brtrue = brfalse = None
                if (br1 > jcc_addr) and (br2 > jcc_addr):
                    brtrue = max(br1, br2)
                    brfalse = min(br1, br2)
                else:
                    brtrue = min(br1, br2)
                    brfalse = max(br1, br2)

                self.jcc_branches[jcc_addr] = ([brtrue, brfalse], cond)

            addrhash = hex(code_address).strip("L") + hex(jcc_addr).strip("L")
            if addrhash not in self.jcc_blks:
                #self.jcc_blks[code_address] = (code_address, jcc_addr)
                self.jcc_blks.append(addrhash)


    def _check_address_sanitify(self, irsb):
        """
        Check the bad and good addresses according to @irsb@
        @param irsb: the IRSB code returned by pyvex
        """
        addrs = []
        bInvalid = False
        for stmt in irsb.statements:
            if stmt.tag != 'Ist_IMark':
                continue
            addr = stmt.addr
            if (addr < self.base_address) or (addr + stmt.len > self.base_address + self.code_length):
                self.logger.debug("Instruction starting at %s has %s bytes, out of range.", hex(addr), str(stmt.len))
                break
            addrs.append(addr)

        #Ending with a invalid instruction or not ending with a branch instruction
        if bInvalid or irsb.jumpkind == 'Ijk_NoDecode':
            for addr in addrs:
                self.black_list.set(addr - self.base_address)

        #We need to collect more JCC-info: all possible code blocks ending with this JCC branch instruction
        #Ending with a direct branch instruction, except JCC
        elif irsb.direct_next and not (irsb.jumpkind == 'Ijk_Boring' and len(irsb.constant_jump_targets) == 2):
            for addr in addrs:
                self.white_list.set(addr - self.base_address)

        else:
            pass

    def create_gadgets_from_instructions(self, address):
        """
        @param code: the code sled for creating gadgets;
        @param address: the start virtual address of @code@
        @param batch_mode: create all possible gadgets in the code sled, if true;
        Otherwise, only create the gadgets starting at @address@

        @return: the created gadget list
        """
        #The address is out of range
        if (address < self.base_address) or (address >= self.base_address + self.code_length):
            return []
        offset = address - self.base_address

        #The code pointer starting at address is blacked or whited out!
        if self.black_list.test(offset) or self.white_list.test(offset):
            return []

        irsbs = self.get_irsbs(address)
        if len(irsbs) < 1:
            return []

        #black-list bad address and white-list good address
        self._check_address_sanitify(irsbs[0])

        #Collect JCC information
        if (irsbs[0].jumpkind == 'Ijk_Boring' and irsbs[0].direct_next and len(irsbs[0].constant_jump_targets) == 2):
            self._extract_jcc_info(irsbs[0], address)

        #Direct jumps are not interesting
        if irsbs[0].direct_next or irsbs[0].jumpkind == 'Ijk_NoDecode':
            return []

        #create gadgets
        stmts = irsbs[0].statements

        gadgets = []
        for irsb in irsbs: #{
            while True: #{
                stmts = irsb.statements
                while len(stmts) > 0 and stmts[0].tag != 'Ist_IMark':
                    stmts.pop(0)
                if len(stmts) == 0:
                    break
                #create one gadget
                addr = stmts[0].addr
                offset = addr - self.base_address
                if offset >= self.code_length:
                    break;
                elif not self.white_list.test(offset):  #We have already create a gadget starting at current address
                    gadgets += self._create_gadgets_from_instructions(addr, irsbs)
                    self.white_list.set(offset)
                stmts.pop(0)
            #}end while
        #}end for

        return gadgets

    def harvest_jcc_gadgets(self, classic_gadget_list):
        """
        Collect if-gadgets.
        @INPUT classic_gadget_list: A list of classical gadgets.
        """
        classic_gadgets = {}
        for g in classic_gadget_list:
            classic_gadgets[long(g.address)] = g

        #Four scenario: the current JCC instruction followed by two classical gadgets, etc
        jcc_GG = {}
        jcc_GJ = {}
        jcc_JG = {}
        jcc_JJ = {}
        classic_gadget_addrs = classic_gadgets.keys()
        for addr, ([brt, brf], cond) in self.jcc_branches.items(): #{
            bf = brf in classic_gadget_addrs
            bt = brt in classic_gadget_addrs
            #both branches are classic gadgets
            if (bf and bt):
                jcc_GG[addr] = (cond, True, classic_gadgets[brf], True, classic_gadgets[brt])
            #only one branch is classic gadget, another one is basic block ended with a jcc instruction
            elif bf:
                jcc_GJ[addr] = (cond, True, classic_gadgets[brf], False, brt)
            elif bt:
                jcc_JG[addr] = (cond, False, brf, True, classic_gadgets[brt])
            else:
                jcc_JJ[addr] = (cond, brf, brt)
        #}end for

        #Scenario I: both branches are gadgets;
        jcc_GG_gadgets = {}
        jcc_GG_psudogadgets = {}
        for addr, (cond, _true1, g1, _true2, g2) in jcc_GG.items(): #{
            if check_acceptable_jccgagdet(g1, g2):
                jcc_GG_gadgets[addr] = (cond, g1, g2)
            else:
                jcc_GG_psudogadgets[addr] = (cond, g1, g2)
        #}end for

        #Only one branch is a gadget, and another one is a basic block ended with jcc.
        #we require the false branch of that jcc is a gadget
        jcc_JG_gadgets = {}
        jcc_JG_psudogadgets = {}
        jcc_GX_addrs = jcc_GG.keys() + jcc_GJ.keys();
        for addr, (cond, _false, brf, _true, g1) in jcc_JG.items():#{
            for addr_next in jcc_GX_addrs:
                if not (brf< addr_next < (brf+0xff)):
                    continue
                addrhash = hex(brf).strip("L") + hex(addr_next).strip("L")
                if addrhash not in self.jcc_blks:
                    continue

                #fix me: enforcing constraints!

                #check validation
                (_cond, _true, g2, _false, _brt) = jcc_GG[addr_next] if addr_next in jcc_GG else jcc_GJ[addr_next]
                if check_acceptable_jccgagdet(g2, g1):
                    jcc_JG_gadgets[addr] = (cond, g2, g1)
                else:
                    jcc_JG_psudogadgets[addr] = (cond, g2, g1)
        #}end for

        jcc_GJ_gadgets = {}
        jcc_GJ_psudogadgets = {}
        for addr, (cond, _true, g1, _false, brt) in jcc_GJ.items():#{
            for addr_next in jcc_GX_addrs:
                if not ((brt-0xff) < addr_next < (brt+0xff)):
                    continue
                addrhash = hex(brt).strip("L") + hex(addr_next).strip("L")
                if addrhash not in self.jcc_blks:
                    continue

                #fix me: enforcing constraints!

                #check validation
                (_cond, _bfalse, g2, _true, _brt) = jcc_GG[addr_next] if addr_next in jcc_GG else jcc_GJ[addr_next]
                if check_acceptable_jccgagdet(g1, g2):
                    jcc_GJ_gadgets[addr] = (cond, g1, g2)
                else:
                    jcc_GJ_psudogadgets[addr] = (cond, g1, g2)
        #}end for

        #Scenario IV: both branches are ended with JCC instructions;
        jcc_JJ_gadgets = {}
        jcc_JJ_psudogadgets = {}
        for addr, (cond, brf, brt) in jcc_JJ.items():#{
            nextt = None
            nextf = None
            for addr_next in jcc_GX_addrs:
                if not ((brt-0xff) < addr_next < (brt+0xff)):
                    continue
                addrhash = hex(brt).strip("L") + hex(addr_next).strip("L")
                if addrhash in self.jcc_blks:
                    nextt = addr_next
                    break

            for addr_next in jcc_GX_addrs:
                if not (brf< addr_next < (brf+0xff)):
                    continue
                addrhash = hex(brf).strip("L") + hex(addr_next).strip("L")
                if addrhash in self.jcc_blks:
                    nextf = addr_next
                    break
            if (nextt is None) or (nextf is None):
                continue

            #fix me: enforcing constraints!

            #check validation
            (_cond, _bfalse, g1, _true, _brt) = jcc_GG[nextf] if nextf in jcc_GG else jcc_GJ[nextf]
            (_cond, _bfalse, g2, _true, _brt) = jcc_GG[nextt] if nextt in jcc_GG else jcc_GJ[nextt]
            if check_acceptable_jccgagdet(g1, g2):
                jcc_JJ_gadgets[addr] = (cond, g1, g2)
            else:
                jcc_JJ_psudogadgets[addr] = (cond, g1, g2)
        #}end for
        print "jcc_GG:", len(jcc_GG), "jcc_GG_gadgets", len(jcc_GG_gadgets), "jcc_GG_psudogadgets", len(jcc_GG_psudogadgets)
        print "jcc_GJ:", len(jcc_GJ), "jcc_GJ_gadgets", len(jcc_GJ_gadgets), "jcc_GJ_psudogadgets", len(jcc_GJ_psudogadgets)
        print "jcc_JG:", len(jcc_JG), "jcc_JG_gadgets", len(jcc_JG_gadgets), "jcc_JG_psudogadgets", len(jcc_JG_psudogadgets)
        print "jcc_JJ:", len(jcc_JJ), "jcc_JJ_gadgets", len(jcc_JJ_gadgets), "jcc_JJ_psudogadgets", len(jcc_JJ_psudogadgets)

        #Create if-gadgets and returns
        jcc_gadgets = {}
        jcc_gadgets.update(jcc_GG_gadgets)
        jcc_gadgets.update(jcc_GJ_gadgets)
        jcc_gadgets.update(jcc_JG_gadgets)
        jcc_gadgets.update(jcc_JJ_gadgets)
        addrs = jcc_gadgets.keys()
        addrs = sorted(addrs)
        jcc_gadgets_list = []
        for addr in addrs:
            (cond, gfalse, gtrue) = jcc_gadgets[addr]
            gadget = JCC(addr, gtrue, gfalse, cond)
            jcc_gadgets_list.append(gadget)
            self.logger.debug("Found gadget: %s", str(gadget))

        if self.logger.level == logging.DEBUG:
            jcc_psudogadgets = {}
            jcc_psudogadgets.update(jcc_GG_psudogadgets)
            jcc_psudogadgets.update(jcc_GJ_psudogadgets)
            jcc_psudogadgets.update(jcc_JG_psudogadgets)
            jcc_psudogadgets.update(jcc_JJ_psudogadgets)
            addrs = jcc_psudogadgets.keys()
            addrs = sorted(addrs)
            for addr in addrs:
                (cond, gfalse, gtrue) = jcc_psudogadgets[addr]
                gadget = JCC(addr, gtrue, gfalse, cond)
                self.logger.debug("Found psudo gadget: %s", str(gadget))

        return jcc_gadgets_list

class EvaluateState(object):
    def new_random_number(self):
        num = random.randint(0, 2 ** (self.arch.bits - 2))
        num = (num / self.arch.instruction_alignment) * self.arch.instruction_alignment
        return num

    def new_constant(self):
        return self.constant

    def __init__(self, arch):
        self.arch = arch
        self.in_regs = collections.defaultdict(self.new_random_number, {})
        self.in_mem  = collections.defaultdict(self.new_random_number, {})

        self.out_regs = {}
        self.out_mem = {}
        self.reset_tmps()

    def reset_tmps(self):
        self.tmps = {}

    def initialize_to_constant(self, constant = 0):
        self.constant = constant
        self.in_regs = collections.defaultdict(self.new_constant, {})
        self.in_mem  = collections.defaultdict(self.new_constant, {})

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
            return utils.mask(self.out_regs[reg], size)
        return utils.mask(self.in_regs[reg], size)

    def set_mem(self, address, value):
        self.out_mem[address] = value

    def get_mem(self, address, size):
        if address in self.out_mem:
            return utils.mask(self.out_mem[address], size)
        return utils.mask(self.in_mem[address], size)

class PyvexEvaluator(object):

    def __init__(self, state, arch):
        self.arch = arch
        self.state = state

    def emulate_irsbs(self, irsbs):
        for irsb in irsbs:
            self.tyenv = irsb.tyenv
            self.state.reset_tmps()
            for stmt in irsb.statements:
                try:
                    if hasattr(self, stmt.tag):
                        getattr(self, stmt.tag)(stmt)
                    else:
                        self.unknown_statement(stmt)
                except Exception, e:
                    #traceback.print_exc()
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
    def Ist_NoOp(self, stmt):    pass
    def Ist_AbiHint(self, stmt): pass
    def Ist_Exit(self, stmt): pass

    def unknown_statement(self, stmt):
        """Raises a RuntimeError. Used to signify that the current statement is one we don't know how to emulate"""
        err_msg = "Unknown statement: {}".format(stmt.tag)
        raise RuntimeError(err_msg)

    # Expression Emulators

    def Iex_CCall(self, expr):
        # TODO we don't really deal with the flags, and I've only seen this used for x86 flags, so I'm just going to ignore this for now.
        # Perhaps, at some point in the future I'll implement this
        return 0

    def Iex_Get(self, expr):
        return self.state.get_reg(expr.offset, expr.result_size(self.tyenv))

    def Iex_RdTmp(self, argument):
        return self.state.get_tmp(argument.tmp, argument.result_size(self.tyenv))

    def Iex_Load(self, expr):
        address = getattr(self, expr.addr.tag)(expr.addr)
        return self.state.get_mem(address, expr.result_size(self.tyenv))

    def Iex_Const(self, expr):
        return getattr(self, expr.con.tag)(expr.con)

    def Ico_U8(self, constant):
        return utils.mask(constant.value, 8)

    def Ico_U16(self, constant):
        return utils.mask(constant.value, 16)

    def Ico_U32(self, constant):
        return utils.mask(constant.value, 32)

    def Ico_U64(self, constant):
        return utils.mask(constant.value, 64)

    def Iex_Unop(self, expr):
        argument = getattr(self, expr.args[0].tag)(expr.args[0])
        return getattr(self, expr.op)(argument)

    def Iop_64to32(self, argument):
        return utils.mask(argument, 32)

    def Iop_64to16(self, argument):
        return utils.mask(argument, 16)

    def Iop_64to8(self, argument):
        return utils.mask(argument, 8)

    def Iop_64to1(self, argument):
        return utils.mask(argument, 1)

    def Iop_32Uto64(self, argument):
        return utils.mask(argument)

    def Iop_16Uto64(self, argument):
        return utils.mask(argument)

    def Iop_8Uto64(self, argument):
        return utils.mask(argument)

    def Iop_1Uto64(self, argument):
        return utils.mask(argument)

    def sign_convert(self, argument, to_base):
        if argument >= 0:
            return argument
        else:
            return (2 ** to_base) + argument

    def Iop_32Sto64(self, argument): return self.sign_convert(argument, 64)
    def Iop_16Sto64(self, argument): return self.sign_convert(argument, 64)
    def Iop_8Sto64(self, argument):    return self.sign_convert(argument, 64)
    def Iop_16Sto32(self, argument): return self.sign_convert(argument, 32)
    def Iop_8Sto32(self, argument):    return self.sign_convert(argument, 32)
    def Iop_8Sto16(self, argument):    return self.sign_convert(argument, 16)

    def Iex_Binop(self, expr):
        left = getattr(self, expr.args[0].tag)(expr.args[0])
        right = getattr(self, expr.args[1].tag)(expr.args[1])
        return getattr(self, expr.op)(left, right)

    def Iop_And64(self, left, right): return left & right
    def Iop_And32(self, left, right): return left & right
    def Iop_And16(self, left, right): return left & right
    def Iop_And8(self, left, right):    return left & right

    def Iop_Xor64(self, left, right): return left ^ right
    def Iop_Xor32(self, left, right): return left ^ right
    def Iop_Xor16(self, left, right): return left ^ right
    def Iop_Xor8(self, left, right):    return left ^ right

    def Iop_Or64(self, left, right): return left | right
    def Iop_Or32(self, left, right): return left | right
    def Iop_Or16(self, left, right): return left | right
    def Iop_Or8(self, left, right):    return left | right

    def Iop_Add64(self, left, right): return utils.mask(left + right)
    def Iop_Add32(self, left, right): return utils.mask(left + right, 32)
    def Iop_Add16(self, left, right): return utils.mask(left + right, 16)
    def Iop_Add8(self, left, right):    return utils.mask(left + right, 8)

    def Iop_Sub64(self, left, right): return utils.mask(left - right)
    def Iop_Sub32(self, left, right): return utils.mask(left - right, 32)
    def Iop_Sub16(self, left, right): return utils.mask(left - right, 16)
    def Iop_Sub8(self, left, right):    return utils.mask(left - right, 8)

    def Iop_Mul64(self, left, right): return utils.mask(left * right)
    def Iop_Mul32(self, left, right): return utils.mask(left * right, 32)
    def Iop_Mul16(self, left, right): return utils.mask(left * right, 16)
    def Iop_Mul8(self, left, right):    return utils.mask(left * right, 8)

    def Iop_Shl64(self, left, right): return utils.mask(left << right)
    def Iop_Shl32(self, left, right): return utils.mask(left << right, 32)
    def Iop_Shl16(self, left, right): return utils.mask(left << right, 16)
    def Iop_Shl8(self, left, right):    return utils.mask(left << right, 8)

    def Iop_Shr64(self, left, right): return utils.mask(left >> right)
    def Iop_Shr32(self, left, right): return utils.mask(left >> right, 32)
    def Iop_Shr16(self, left, right): return utils.mask(left >> right, 16)
    def Iop_Shr8(self, left, right):    return utils.mask(left >> right, 8)

    def Iop_Sal64(self, left, right): return utils.mask(left >> right)
    def Iop_Sal32(self, left, right): return utils.mask(left >> right, 32)
    def Iop_Sal16(self, left, right): return utils.mask(left >> right, 16)
    def Iop_Sal8(self, left, right):    return utils.mask(left >> right, 8)

    def Iop_Sar64(self, left, right): return utils.mask(left >> right)
    def Iop_Sar32(self, left, right): return utils.mask(left >> right, 32)
    def Iop_Sar16(self, left, right): return utils.mask(left >> right, 16)
    def Iop_Sar8(self, left, right):    return utils.mask(left >> right, 8)

    def Iop_CmpEQ64(self, left, right): return 1 if utils.mask(left, 64) == utils.mask(right, 64) else 0
    def Iop_CmpEQ32(self, left, right): return 1 if utils.mask(left, 32) == utils.mask(right, 32) else 0
    def Iop_CmpEQ16(self, left, right): return 1 if utils.mask(left, 16) == utils.mask(right, 16) else 0
    def Iop_CmpEQ8(self, left, right): return 1 if utils.mask(left, 8) == utils.mask(right, 8) else 0

    def Iop_CmpNE64(self, left, right): return 1 if utils.mask(left, 64) != utils.mask(right, 64) else 0
    def Iop_CmpNE32(self, left, right): return 1 if utils.mask(left, 32) != utils.mask(right, 32) else 0
    def Iop_CmpNE16(self, left, right): return 1 if utils.mask(left, 16) != utils.mask(right, 16) else 0
    def Iop_CmpNE8(self, left, right): return 1 if utils.mask(left, 8) != utils.mask(right, 88) else 0

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print "Usage: classifier.py architecture filename [-v]"
        sys.exit(1)

    arch = archinfo.arch_from_id(sys.argv[1]).__class__
    code = utils.get_contents(sys.argv[2])

    classifier = GadgetClassifier(arch, log_level = logging.DEBUG if len(sys.argv) > 3 else logging.WARNING)
    gadgets = classifier.create_gadgets_from_instructions(code, 0x40000)
    for g in gadgets:
        print g

    print "try to find jcc gadget"
    jcc_gadgets = classifier.harvest_jcc_gadgets(gadgets)
    for g in jcc_gadgets:
        print g
