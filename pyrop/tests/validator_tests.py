import unittest, logging
import pyvex, archinfo

from gadget import *
from validator import *

def r(a, n):
  return a.registers[n][0]

class ClassifierTests(unittest.TestCase):

  def run_test(self, arch, tests):
    validator = Validator(arch)

    for code, gadget in tests:
      irsb = pyvex.IRSB(code, 0x40000, arch)
      irsb.pp()
      result = validator.validate_gadget(gadget, irsb)

  def test_amd64(self):
    arch = archinfo.ArchAMD64()
    tests = [
      ('\x5f\xc3', LoadMem(arch, 0x40000, [r(arch, 'rsp')], r(arch, 'rdi'), [0], [], 0x10, 0x8)), # pop rdi; ret
    ]
    self.run_test(arch, tests)


if __name__ == '__main__':
  unittest.main()
