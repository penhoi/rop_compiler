# This file holds the gadget synthesizer.

import collections, logging, random, sys
import pyvex, archinfo

from gadget import *

class GadgetSynthesizer(object):
  """This class is used to combine gadgets to create the desired one"""

  def __init__(self, arch, gadgets, log_level = logging.WARNING):
    logging.basicConfig(format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    self.logger = logging.getLogger(self.__class__.__name__)
    self.logger.setLevel(log_level)

    self.gadgets = gadgets
    self.arch = arch()

  def create_new_gadgets(self, gadget_type, inputs, output, no_clobber):
    return None

if __name__ == "__main__":
  class FakeIrsb:
    def __init__(self): self._addr = 0x40000

  # A simple set of tests to ensure we can correctly synthesize some example gadgets
  tests = {
    archinfo.ArchAMD64 : {
      (LoadMem, None, 16, ()) : [
        MoveReg(archinfo.ArchAMD64(), FakeIrsb(), [16], 40, [], [], 8, 4),
        LoadMem(archinfo.ArchAMD64(), FakeIrsb(), [48], 16, [], [], 8, 4)
      ]
    },
    archinfo.ArchMIPS64 : {
    },
    archinfo.ArchPPC64 : {
    },
    archinfo.ArchARM : {
    }
  }
  #import sys
  #arch = archinfo.ArchAMD64
  #tests = { arch : tests[arch] }

  fail = False
  for arch, arch_tests in tests.items():
    print "\n{} Tests:".format(arch.name)

    for ((desired_type, inputs, output, no_clobber), gadgets) in arch_tests.items():
      synthesizer = GadgetSynthesizer(arch, gadgets, logging.DEBUG)
      result_gadget = synthesizer.create_new_gadgets(desired_type, inputs, output, no_clobber)

      if result_gadget == None: # If we didn't get the gadget we want
        fail = True
        print "\nCouldn't create the gadget {}".format(desired_type.__name__)

  if fail:
    print "\nFAILURE!!! One or more incorrectly classified gadgets"
  else:
    print "\nSUCCESS, all gadgets correctly classified"

