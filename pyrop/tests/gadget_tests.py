import unittest, logging
import pyvex, archinfo

from gadget import *
from validator import *

def n2r(arch, reg_name):
  return arch.registers[reg_name][0]

class GadgetTests(unittest.TestCase):

  def run_test(self, arch, tests):
    validator = Validator(arch)

    for test in tests:
      desired_type, inputs, outputs, no_clobbers, gadget_list = self.make_test(arch, test)
      print "Trying to get a {}(inputs=[{}], output={}, no_clobbers=[{}])".format(desired_type, 
        ", ".join([arch.translate_register_name(i) for i in inputs]),
        ", ".join([arch.translate_register_name(o) for o in outputs]),
        ", ".join([arch.translate_register_name(nc) for nc in no_clobbers]))

      result_gadget = gadget_list.create_new_gadgets(desired_type, inputs, outputs, no_clobbers)
      self.assertNotEqual(result_gadget, None)
      self.assertNotEqual(type(result_gadget), desired_type)

  def make_gadget_list(self, arch, gadgets):
    gadget_list = GadgetList(log_level = logging.DEBUG)
    for (gadget_type, gadget_inputs, gadget_outputs, params, clobber, stack_offset, ip_in_stack_offset) in gadgets:
      gadget_input_regs = []
      for input_reg_name in gadget_inputs:
        gadget_input_regs.append(n2r(arch, input_reg_name))

      gadget_output_regs = []
      for gadget_output_reg_name in gadget_outputs:
        gadget_output_regs.append(n2r(arch, gadget_output_reg_name))

      gadget_clobber_reg = []
      for clobber_reg_name in clobber:
        gadget_clobber_reg.append(n2r(arch, clobber_reg_name))

      gadget = gadget_type(arch, 0x40000, gadget_input_regs, gadget_output_regs, params, gadget_clobber_reg, stack_offset, ip_in_stack_offset)
      gadget_list.add_gadget(gadget)
    return gadget_list

  def make_test(self, arch, test):
    desired_type, inputs, outputs, no_clobbers, gadgets = test
    gadget_list = self.make_gadget_list(arch, gadgets)

    input_regs = []
    for input_reg_name in inputs:
      input_regs.append(n2r(arch, input_reg_name))

    no_clobber_regs = []
    for no_clobber_reg_name in no_clobbers:
      no_clobber_regs.append(n2r(arch, no_clobber_reg_name))

    output_regs = []
    for output_reg_name in outputs:
      output_regs.append(n2r(arch, output_reg_name))

    return desired_type, input_regs, output_regs, no_clobber_regs, gadget_list

  def test_amd64(self):
    arch = archinfo.ArchAMD64()
    tests = [
      (LoadMem, [], ['rax'], [], [
        (MoveReg, ['rbx'], ['rax'], [], [], 8, 4),
        (LoadMem, ['rsp'], ['rbx'], [], [], 8, 4)
      ]),
      (LoadMem, ['rsp'], ['rax'], [], [
        (LoadMemJump, ['rsp', 'rbx'], ['rax'], [], [], 8, None),
        (LoadMem,     ['rsp'],        ['rbx'], [], [], 8, 4)
      ]),
    ]
    self.run_test(arch, tests)

  def test_create_load_registers_chain(self):
    a = archinfo.ArchAMD64()
    gadget_list = self.make_gadget_list(a, [(LoadMultiple, ['rsp'], ['rax', 'rbx', 'rcx'], [0, 8, 0x10], [], 0x20, 0x18)])
    chain = gadget_list.create_load_registers_chain(0x4343434343434343, n2r(a, 'rsp'), {n2r(a, 'rax') : 0x4141414141414141, n2r(a, 'rbx') : 0x4242424242424242})
    self.assertEqual(chain[0:8],   "AAAAAAAA") # check rax
    self.assertEqual(chain[8:16],  "BBBBBBBB") # check rbx
    self.assertEqual(chain[24:32], "CCCCCCCC") # Check rip
    self.assertEqual(len(chain), 0x20)

  def skip_test_arm(self):
    arch = archinfo.ArchARM()
    tests = [
    ]
    self.run_test(arch, tests)

  def skip_test_mips(self):
    arch = archinfo.ArchMIPS32('Iend_BE')
    tests = [
    ]
    self.run_test(arch, tests)

  def skip_test_ppc(self):
    arch = archinfo.ArchPPC32()
    tests = [
    ]
    self.run_test(arch, tests)

if __name__ == '__main__':
  unittest.main()
