import logging
import finder, goal, scheduler

def rop(filenames_and_addresses, goals, log_level = logging.WARNING):
  """Takes a set of goals and creates a rop chain for it"""
  all_gadgets = []
  for filename, address in filenames_and_addresses:
    gadget_finder = finder.Finder(filename, address, log_level)
    all_gadgets.extend(gadget_finder.find_gadgets())

  gadget_scheduler = scheduler.Scheduler(all_gadgets, goals)

  #TODO the rest of this
  return "TODO"


def rop_to_shellcode(filenames_and_addresses, shellcode_address, log_level = logging.WARNING):
  """Convience method to create a goals json and then find a rop chain for it"""
  goal_json = '{ "goals" : [ [ "shellcode", %d ] ] }' % shellcode_address
  goal_resolver = goal.GoalResolver(goal_json, log_level)

  return rop(filenames_and_addresses, goal_resolver.get_goals(), log_level)


if __name__ == "__main__":
  import sys
  if len(sys.argv) < 2:
    print "Usage: python ropme.py filename"
    sys.exit(0)

  rop = rop_to_shellcode([(sys.argv[1], 0x4000000)], 0x7fff000)
  print rop

