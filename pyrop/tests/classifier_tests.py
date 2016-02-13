import unittest, logging
import archinfo

from gadget import *
import classifier

class ClassifierTests(unittest.TestCase):

  def run_test(self, gadget_classifier, tests):
    for (expected_types, code) in tests:
      gadgets = gadget_classifier.create_gadgets_from_instructions(code, 0x40000)

      # For each returned gadget, count the number of each gadget types
      types = {}
      for g in gadgets:
        if type(g) not in types: types[type(g)] = 0
        types[type(g)] += 1
      self.assertEqual(types, expected_types)

  def test_amd64(self):
    gadget_classifier = classifier.GadgetClassifier(archinfo.ArchAMD64(), logging.DEBUG)
    tests = [
      ({Jump : 1},            '\xff\xe0'),                                                # jmp rax
      ({MoveReg : 2},         '\x48\x93\xc3'),                                            # xchg rbx, rax; ret
      ({MoveReg : 1},         '\x48\x89\xcb\xc3'),                                        # mov rbx,rcx; ret
      ({LoadConst : 1},       '\x48\xbb\xff\xee\xdd\xcc\xbb\xaa\x99\x88\xc3'),            # movabs rbx,0x8899aabbccddeeff; ret
      ({AddGadget : 1},       '\x48\x01\xc3\xc3'),                                        # add rbx, rax; ret
      ({LoadMem : 1},         '\x5f\xc3'),                                                # pop rdi; ret
      ({LoadMem : 1},         '\x48\x8b\x43\x08\xc3'),                                    # mov rax,QWORD PTR [rbx+0x8]; ret
      ({LoadMem : 1},         '\x48\x8b\x07\xc3'),                                        # mov rax,QWORD PTR [rdi]; ret
      ({StoreMem : 1},        '\x48\x89\x03\xc3'),                                        # mov QWORD PTR [rbx],rax; ret
      ({StoreMem : 1},        '\x48\x89\x43\x08\xc3'),                                    # mov QWORD PTR [rbx+0x8],rax; ret
      ({StoreMem : 1},        '\x48\x89\x44\x24\x08\xc3'),                                # mov QWORD PTR [rsp+0x8],rax; ret
      ({LoadAddGadget: 1},    '\x48\x03\x03\xc3'),                                        # add rax,QWORD PTR [rbx]
      ({StoreAddGadget: 1},   '\x48\x01\x43\xf8\xc3'),                                    # add QWORD PTR [rbx-0x8],rax; ret
      ({},                    '\x48\x39\xeb\xc3'),                                        # cmp rbx, rbp; ret
      ({},                    '\x5e'),                                                    # pop rsi
      ({},                    '\x8b\x04\xc5\xc0\x32\x45\x00\xc3'),                        # mov rax,QWORD PTR [rax*8+0x4532c0]
      ({LoadMem : 1, LoadConst : 1}, '\x59\x48\x89\xcb\x48\xc7\xc1\x05\x00\x00\x00\xc3'), # pop rcx; mov rbx,rcx; mov rcx,0x5; ret
      ({},                    '\x48\x8b\x85\xf0\xfd\xff\xff\x48\x83\xc0'),
#      ({LoadMemJump : 1, },   '\x5a\xfc\xff\xd0'),                                        # pop rdx, cld, call rax
    ]
    self.run_test(gadget_classifier, tests)

  def test_arm(self):
    gadget_classifier = classifier.GadgetClassifier(archinfo.ArchARM(), logging.DEBUG)
    tests = [
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
    self.run_test(gadget_classifier, tests)

  def skip_test_mips(self):
    gadget_classifier = classifier.GadgetClassifier(archinfo.ArchMIPS32('Iend_BE'), logging.DEBUG)
    tests = [
      ({LoadMem : 1},
        '\x8f\xbf\x00\x10' + # lw ra,16(sp)
        '\x8f\xb0\x00\x08' + # lw s0,8(sp)
        '\x03\xe0\x00\x08' + # jr ra
        '\x00\x00\x00\x00')  # nop
    ]
    self.run_test(gadget_classifier, tests)

  def test_ppc(self):
    gadget_classifier = classifier.GadgetClassifier(archinfo.ArchPPC32(), logging.DEBUG)
    tests = [
      ({LoadMem : 1},
        '\x08\x00\xe1\x83' + # lwz r31,8(r1)
        '\x04\x00\x01\x80' + # lwz r0,4(r1)
        '\xa6\x03\x08\x7c' + # mtlr r0
        '\x10\x00\x21\x38' + # addi r1,r1,16
        '\x20\x00\x80\x4e')  # blr
    ]
    self.run_test(gadget_classifier, tests)

if __name__ == '__main__':
  unittest.main()
