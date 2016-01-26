# This file contains a few convenience methods that wrap the ROP compiling process that can be used by exploit scripts.
import logging
import archinfo
import finder, goal, scheduler

def rop(filenames_and_addresses, goal_resolver, arch = archinfo.ArchAMD64, log_level = logging.WARNING):
  """Takes a goal resolver and creates a rop chain for it"""
  all_gadgets = []
  for filename, address in filenames_and_addresses:
    gadget_finder = finder.Finder(filename, arch, address, log_level)
    all_gadgets.extend(gadget_finder.find_gadgets())

  gadget_scheduler = scheduler.Scheduler(all_gadgets, goal_resolver, arch, log_level)
  return gadget_scheduler.get_chain()

def rop_to_shellcode(filenames_and_addresses, shellcode_address, arch = archinfo.ArchAMD64, log_level = logging.WARNING):
  """Convience method to create a goal_resolver for a shellcode address goal then find a rop chain for it"""
  goal_resolver = goal.create_from_arguments(filenames_and_addresses, [], [["shellcode", hex(shellcode_address)]])
  return rop(filenames_and_addresses, goal_resolver, arch, log_level)

if __name__ == "__main__":
  import sys
  if len(sys.argv) < 2:
    print "Usage: python ropme.py filename [-v]"
    sys.exit(0)

  level = logging.WARNING
  if len(sys.argv) > 2 and sys.argv[2] == "-v":
    level = logging.DEBUG

  rop = rop_to_shellcode([(sys.argv[1], 0)], 0x7fff124, archinfo.ArchARM, level)
  print rop

