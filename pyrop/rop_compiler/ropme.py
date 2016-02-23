# This file contains a few convenience methods that wrap the ROP compiling process that can be used by exploit scripts.
import logging
import archinfo
import goal, scheduler, multifile_handler, gadget

def rop(files, libraries, goal_list, arch = archinfo.ArchAMD64(), log_level = logging.WARNING, validate_gadgets = False, strategy = None):
  """Takes a goal resolver and creates a rop chain for it"""
  file_handler = multifile_handler.MultifileHandler(files, libraries, arch, log_level)
  goal_resolver = goal.GoalResolver(file_handler, goal_list, log_level)

  gadgets = file_handler.find_gadgets(validate_gadgets)
  if strategy != None:
    gadgets.set_strategy(strategy)
  gadget_scheduler = scheduler.Scheduler(gadgets, goal_resolver, file_handler, arch, log_level)
  return gadget_scheduler.get_chain()

def rop_to_shellcode(files, libraries, shellcode_address, arch = archinfo.ArchAMD64(), log_level = logging.WARNING, validate_gadgets = False):
  """Convience method to create a goal_resolver for a shellcode address goal then find a rop chain for it"""
  goal_list = [["shellcode", hex(shellcode_address)]]
  return rop(files, libraries, goal_list, arch, log_level, validate_gadgets)

