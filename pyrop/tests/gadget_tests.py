import unittest, logging
import pyvex, archinfo

from gadget import *
import utils

def n2r(arch, reg_name):
  return arch.registers[reg_name][0]

class GadgetTests(unittest.TestCase):

  def run_test(self, arch, tests):
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
    for (addr, gadget_type, gadget_inputs, gadget_outputs, params, clobber, stack_offset, ip_in_stack_offset) in gadgets:
      gadget_input_regs = []
      for input_reg_name in gadget_inputs:
        gadget_input_regs.append(n2r(arch, input_reg_name))

      gadget_output_regs = []
      for gadget_output_reg_name in gadget_outputs:
        gadget_output_regs.append(n2r(arch, gadget_output_reg_name))

      gadget_clobber_reg = []
      for clobber_reg_name in clobber:
        gadget_clobber_reg.append(n2r(arch, clobber_reg_name))

      gadget = gadget_type(arch, addr, gadget_input_regs, gadget_output_regs, params, gadget_clobber_reg, stack_offset, ip_in_stack_offset)
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
        (0x40000, MoveReg, ['rbx'], ['rax'], [], [], 8, 4),
        (0x40000, LoadMem, ['rsp'], ['rbx'], [], [], 8, 4)
      ]),
      (LoadMem, ['rsp'], ['rax'], [], [
        (0x40000, LoadMemJump, ['rsp', 'rbx'], ['rax'], [], [], 8, None),
        (0x40000, LoadMem,     ['rsp'],        ['rbx'], [], [], 8, 4)
      ]),
    ]
    self.run_test(arch, tests)

  def test_create_load_registers_chain(self):
    a = archinfo.ArchAMD64()
    gadget_list = self.make_gadget_list(a, [
      (0x40000, LoadMultiple, ['rsp'], ['rax', 'rbx', 'rcx', 'rdi'], [0, 8, 0x10], [], 0x28, 0x20),
      (0x40000, LoadMem,      ['rsp'], ['rax'], [0x00], ['rbx','rcx', 'rdi'], 0x28, 0x20),
      (0x40000, LoadMem,      ['rsp'], ['rbx'], [0x08], ['rax','rcx', 'rdi'], 0x28, 0x20),
      (0x40000, LoadMem,      ['rsp'], ['rcx'], [0x10], ['rbx','rax', 'rdi'], 0x28, 0x20),
      (0x40000, LoadMem,      ['rsp'], ['rdi'], [0x18], ['rbx','rcx', 'rax'], 0x28, 0x20),

      (0x40100, LoadMultiple, ['rsp'], ['rax', 'rbx', 'rcx'], [0, 8, 0x10], [], 0x20, 0x18),
      (0x40100, LoadMem,      ['rsp'], ['rax'], [0x00], ['rbx','rcx'], 0x20, 0x18),
      (0x40100, LoadMem,      ['rsp'], ['rbx'], [0x08], ['rax','rcx'], 0x20, 0x18),
      (0x40100, LoadMem,      ['rsp'], ['rcx'], [0x10], ['rbx','rax'], 0x20, 0x18),

      (0x40200, LoadMultiple, ['rsp'], ['rax', 'rbx'], [0, 8], [], 0x18, 0x10),
      (0x40200, LoadMem,      ['rsp'], ['rax'], [0x00], ['rbx'], 0x18, 0x10),
      (0x40200, LoadMem,      ['rsp'], ['rbx'], [0x08], ['rax'], 0x18, 0x10),

      (0x40300, LoadMem,      ['rsp'], ['rdx'], [0x00], [], 0x10, 0x8),
      (0x40400, LoadMem,      ['rsp'], ['rsi'], [0x00], [], 0x10, 0x8),
      (0x40500, LoadMem,      ['rsp'], ['rbp'], [0x00], [], 0x10, 0x8),
      (0x40600, LoadConst,    ['rsp'], ['rdi'], [0x4141414141414141], [], 0x8, 0x0),
      (0x40700, MoveReg,      ['rdx'], ['r10'], [], [], 0x8, 0x0),
      (0x40800, MoveReg,      ['rdx'], ['r11'], [], [], 0x8, 0x0),
    ])

    register_values = {n2r(a, 'rax') : 0x4141414141414141, n2r(a, 'rbx') : 0x4242424242424242}
    chain, first_address = gadget_list.create_load_registers_chain(0x4343434343434343, n2r(a, 'rsp'), register_values)
    self.assertNotEqual(chain, None)
    self.assertEqual(first_address, 0x40200)
    self.assertEqual(chain[0:8],   "AAAAAAAA") # check rax
    self.assertEqual(chain[8:16],  "BBBBBBBB") # check rbx
    self.assertEqual(chain[16:24], "CCCCCCCC") # Check rip
    self.assertEqual(len(chain), 0x18)

    register_values = {n2r(a, 'rax') : 0x4141414141414141, n2r(a, 'rbx') : 0x4242424242424242, n2r(a, 'rcx') : 0x4343434343434343}
    chain, first_address = gadget_list.create_load_registers_chain(0x4444444444444444, n2r(a, 'rsp'), register_values)
    self.assertNotEqual(chain, None)
    self.assertEqual(first_address, 0x40100)
    self.assertEqual(chain[0:8],   "AAAAAAAA") # check rax
    self.assertEqual(chain[8:16],  "BBBBBBBB") # check rbx
    self.assertEqual(chain[16:24], "CCCCCCCC") # Check rcx
    self.assertEqual(chain[24:32], "DDDDDDDD") # Check rip
    self.assertEqual(len(chain), 0x20)

    register_values = {n2r(a, 'rax') : 0x4141414141414141}
    chain, first_address = gadget_list.create_load_registers_chain(0x4343434343434343, n2r(a, 'rsp'), register_values)
    self.assertNotEqual(chain, None)
    self.assertEqual(first_address, 0x40200)
    self.assertEqual(chain[0:8],   "AAAAAAAA") # check rax
    self.assertEqual(chain[16:24], "CCCCCCCC") # Check rip
    self.assertEqual(len(chain), 0x18)

    register_values = {n2r(a, 'rbx') : 0x4141414141414141}
    chain, first_address = gadget_list.create_load_registers_chain(0x4343434343434343, n2r(a, 'rsp'), register_values)
    self.assertNotEqual(chain, None)
    self.assertEqual(first_address, 0x40200)
    self.assertEqual(chain[8:16],  "AAAAAAAA") # check rbx
    self.assertEqual(chain[16:24], "CCCCCCCC") # Check rip
    self.assertEqual(len(chain), 0x18)

    register_values = {n2r(a, 'rdx') : 0x4141414141414141}
    chain, first_address = gadget_list.create_load_registers_chain(0x4343434343434343, n2r(a, 'rsp'), register_values)
    self.assertNotEqual(chain, None)
    self.assertEqual(first_address, 0x40300)
    self.assertEqual(chain[0:8],  "AAAAAAAA") # check rdx
    self.assertEqual(chain[8:16], "CCCCCCCC") # Check rip
    self.assertEqual(len(chain), 0x10)

    register_values = {n2r(a, 'rdi') : 0x4141414141414141}
    chain, first_address = gadget_list.create_load_registers_chain(0x4343434343434343, n2r(a, 'rsp'), register_values)
    self.assertNotEqual(chain, None)
    self.assertEqual(first_address, 0x40600)
    self.assertEqual(chain[0:8], "CCCCCCCC") # Check rip
    self.assertEqual(len(chain), 0x8)

    register_values = { n2r(a, 'rax') : 0x4141414141414141, n2r(a, 'rbx') : 0x4242424242424242,
      n2r(a, 'rcx') : 0x4343434343434343, n2r(a, 'rdx') : 0x4444444444444444 }
    chain, first_address = gadget_list.create_load_registers_chain(0x4545454545454545, n2r(a, 'rsp'), register_values)
    self.assertNotEqual(chain, None)
    self.assertEqual(first_address, 0x40100)
    self.assertEqual(chain[0:8],   "AAAAAAAA") # check rax
    self.assertEqual(chain[8:16],  "BBBBBBBB") # check rbx
    self.assertEqual(chain[16:24], "CCCCCCCC") # check rcx
    self.assertEqual(chain[24:32], utils.ap(0x40300 ,a)) # Check next gadget address
    self.assertEqual(chain[32:40], "DDDDDDDD") # check rdx
    self.assertEqual(chain[40:48], "EEEEEEEE") # check final rip
    self.assertEqual(len(chain), 48)

    register_values = { n2r(a, 'rdx') : 0x4141414141414141, n2r(a, 'rsi') : 0x4242424242424242, n2r(a, 'rbp') : 0x4343434343434343 }
    chain, first_address = gadget_list.create_load_registers_chain(0x4444444444444444, n2r(a, 'rsp'), register_values)
    self.assertNotEqual(chain, None)
    self.assertEqual(first_address, 0x40300)
    self.assertEqual(chain[0:8],   "AAAAAAAA") # check rdx
    self.assertEqual(chain[8:16],  utils.ap(0x40400 ,a)) # Check next gadget address
    self.assertEqual(chain[16:24], "BBBBBBBB") # check rsi
    self.assertEqual(chain[24:32], utils.ap(0x40500 ,a)) # Check next gadget address
    self.assertEqual(chain[32:40], "CCCCCCCC") # check rsi
    self.assertEqual(chain[40:48], "DDDDDDDD") # check final address
    self.assertEqual(len(chain), 48)

    register_values = { n2r(a, 'r10') : 0x4141414141414141, n2r(a, 'r11') : 0x4242424242424242 }
    chain, first_address = gadget_list.create_load_registers_chain(0x4343434343434343, n2r(a, 'rsp'), register_values)
    self.assertNotEqual(chain, None)
    self.assertEqual(first_address, 0x40300)
    self.assertEqual(chain[0:8],   "AAAAAAAA") # check rdx
    self.assertEqual(chain[8:16],  utils.ap(0x40700, a)) # check the next gadget address
    self.assertEqual(chain[16:24], utils.ap(0x40300, a)) # check the next gadget address
    self.assertEqual(chain[24:32], "BBBBBBBB") # check rdx
    self.assertEqual(chain[32:40],  utils.ap(0x40800, a)) # check the next gadget address
    self.assertEqual(chain[40:48], "CCCCCCCC") # check rdx
    self.assertEqual(len(chain), 48)

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
