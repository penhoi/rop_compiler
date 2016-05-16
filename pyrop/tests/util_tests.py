import unittest, logging
import archinfo

from rop_compiler.utils import *

class UtilTests(unittest.TestCase):

  def test_amd64(self):
    arch = archinfo.ArchAMD64()
    self.assertTrue(address_contains_bad_byte(0x401234, "\x00", arch))
    self.assertFalse(address_contains_bad_byte(0x7fffffff12345678, "\x00", arch))

if __name__ == '__main__':
  unittest.main()
