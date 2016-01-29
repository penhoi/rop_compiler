# This file holds the gadget synthesizer.
import collections, logging, random, sys
import pyvex, archinfo
import classifier

from gadget import *

class GadgetSynthesizer(classifier.GadgetClassifier):
  """This class is used to combine gadgets to create the desired one"""

  def __init__(self, arch, gadget_list, log_level = logging.WARNING):
    logging.basicConfig(format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    self.logger = logging.getLogger(self.__class__.__name__)
    self.logger.setLevel(log_level)

    self.gadget_list = gadget_list
    self.arch = arch()

  def create_new_gadgets(self, gadget_type, inputs, output, no_clobber):
    return getattr(self, gadget_type.__name__)(inputs, output, no_clobber)

  def LoadMem(self, inputs, output, no_clobber):
    best_move = best_load = None
    best_complexity = sys.maxint
    for move_gadget in self.gadget_list.foreach_type_output(MoveReg, output):
      for load_gadget in self.gadget_list.foreach_type_output(LoadMem, move_gadget.inputs[0]):
        complexity = move_gadget.complexity() + load_gadget.complexity()
        if complexity < best_complexity:
          best_complexity = complexity
          (best_move, best_load) = (move_gadget, load_gadget)

    if best_move != None:
      return CombinedGadget([best_move, best_load])

    return None

if __name__ == "__main__":
  class FakeIrsb:
    def __init__(self, arch):
      self._addr = 0x40000
      self.arch = arch

  # A simple set of tests to ensure we can correctly synthesize some example gadgets
  tests = {
    archinfo.ArchAMD64 : {
      (LoadMem, None, 16, ()) : GadgetList([
        MoveReg(archinfo.ArchAMD64(), FakeIrsb(archinfo.ArchAMD64), [40], 16, [], [], 8, 4),
        LoadMem(archinfo.ArchAMD64(), FakeIrsb(archinfo.ArchAMD64), [48], 40, [], [], 8, 4)
      ])
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

    for ((desired_type, inputs, output, no_clobber), gadget_list) in arch_tests.items():
      synthesizer = GadgetSynthesizer(arch, gadget_list, logging.DEBUG)
      result_gadget = synthesizer.create_new_gadgets(desired_type, inputs, output, no_clobber)
      if result_gadget == None: # If we didn't get the gadget we want
        fail = True
        print "\nCouldn't create the gadget {}".format(desired_type.__name__)

  if fail:
    print "\nFAILURE!!! One or more incorrectly classified gadgets"
  else:
    print "\nSUCCESS, all gadgets correctly classified"

