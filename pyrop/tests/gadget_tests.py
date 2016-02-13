import unittest, logging
import pyvex, archinfo

from gadget import *
from validator import *

class GadgetTests(unittest.TestCase):

  def run_test(self, arch, tests):
    validator = Validator(arch)

    for test in tests:
      desired_type, inputs, output, no_clobbers, gadget_list = self.make_test(arch, test)
      print "Trying to get a {}(inputs=[{}], output={}, no_clobbers=[{}])".format(desired_type, 
        ", ".join([arch.translate_register_name(i) for i in inputs]), arch.translate_register_name(output),
        ", ".join([arch.translate_register_name(nc) for nc in no_clobbers]))

      result_gadget = gadget_list.create_new_gadgets(desired_type, inputs, output, no_clobbers)
      self.assertNotEqual(result_gadget, None)
      self.assertNotEqual(type(result_gadget), desired_type)

  def make_test(self, arch, test):
    desired_type, inputs, output, no_clobbers, gadgets = test

    gadget_list = GadgetList(log_level = logging.DEBUG)
    for (gadget_type, gadget_inputs, gadget_output, params, clobber, stack_offset, ip_in_stack_offset) in gadgets:
      gadget_input_regs = []
      for input_reg_name in gadget_inputs:
        gadget_input_regs.append(arch.registers[input_reg_name][0])

      if gadget_output != None:
        gadget_output = arch.registers[gadget_output][0]

      gadget_clobber_reg = []
      for clobber_reg_name in clobber:
        gadget_clobber_reg.append(arch.registers[clobber_reg_name][0])

      gadget = gadget_type(arch, 0x40000, gadget_input_regs, gadget_output, params, gadget_clobber_reg, stack_offset, ip_in_stack_offset)
      gadget_list.add_gadget(gadget)

    input_regs = []
    for input_reg_name in inputs:
      input_regs.append(arch.registers[input_reg_name][0])

    no_clobber_regs = []
    for no_clobber_reg_name in no_clobbers:
      no_clobber_regs.append(arch.registers[no_clobber_reg_name][0])

    return desired_type, input_regs, arch.registers[output][0], no_clobber_regs, gadget_list

  def test_amd64(self):
    arch = archinfo.ArchAMD64()
    tests = [
      (LoadMem, [], 'rax', [], [
        (MoveReg, ['rbx'], 'rax', [], [], 8, 4),
        (LoadMem, ['rsp'], 'rbx', [], [], 8, 4)
      ]),
      (LoadMem, ['rsp'], 'rax', [], [
        (LoadMemJump, ['rsp', 'rbx'], 'rax', [], [], 8, None),
        (LoadMem, ['rsp'],      'rbx', [], [], 8, 4)
      ]),
    ]
    self.run_test(arch, tests)

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
