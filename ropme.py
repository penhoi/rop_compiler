import logging
import finder, goal

def rop(filenames_and_addresses, goals, log_level = logging.WARNING):
  """Takes a set of goals and creates a rop chain for it"""
  all_gadgets = []
  for filename, address in filenames_and_addresses:
    finder = finder.Finder(filename, address, log_level)
    all_gadgets.expand(finder.find_gadgets())

  #TODO the rest of this


def rop_to_shellcode(filenames_and_addresses, shellcode_address, log_level = logging.WARNING):
  """Convience method to create a goals json and then find a rop chain for it"""
  goal_json = '{ "goals" : [ [ "shellcode", %d ] ] }' % shellcode_address
  goal_resolver = goal.GoalResolver(goal_json, log_level)

  return rop(filenames_and_addresses, goal_resolver.get_goals(), log_level)
