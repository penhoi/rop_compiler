import logging
import z3
from ast import *

class Z3Helper(object):

  STACK_SIZE = 0x100
  INPUT_STACK = STACK_SIZE / 2

  def __init__(self, output_level=logging.CRITICAL):
    self.logger = logging.getLogger(self.__class__.__name__)
    self.logger.setLevel(output_level)
    self.output_level = output_level

  def get_memory(self, address):
    return z3.BitVec("Memory_0x{:x}".format(address), 64)

  def get_memory_solver(self):
    s = self.get_solver()
    for i in range(0, self.STACK_SIZE, 8):
      mem_index = self.get_memory(i) 
      s.append(mem_index == i)
    return s

  def get_solver(self):
    s = z3.Solver()
    m = z3.Array("Memory", z3.BitVecSort(64), z3.BitVecSort(64))
    for i in range(0, self.STACK_SIZE, 8):
      mem_index = self.get_memory(i) 
      s.append(m[i] == mem_index)
    s.append(z3.BitVec("rsp_input", 64) == self.INPUT_STACK)
    return s

  def get_values(self, statements):
    print "Statements",statements

    smem = self.get_memory_solver()
    s = self.get_solver()
    for statement in statements:
      z3_statement = statement.to_z3()
      smem.add(z3_statement)
      s.add(z3_statement)

    if smem.check() == z3.unsat:
      return None

    m = smem.model()
    outputs = {}
    for var in m:
      if var.name().find("_output") != -1: # For each output determine if it's a memory read or just a number value
        value = m[var].as_long()
        mem = self.get_memory(value)
        s.push()
        s.add(z3.BitVec(var.name(), 64) != mem)
        if s.check() == z3.unsat: # Then the register was set to that memory 
          outputs[var.name()] = ("M", value - self.INPUT_STACK)
        else:
          outputs[var.name()] = ("R", value - self.INPUT_STACK)
        s.pop()

    return outputs








