import archinfo
import logging, collections
import rop_compiler.factories as factories

import argparse

parser = argparse.ArgumentParser(description="Run the gadget locator on the supplied binary")
parser.add_argument('filename', type=str, default=None, help='The file (executable/library) to load gadgets from')
parser.add_argument('-arch', type=str, default="AMD64", help='The architecture of the binary')
parser.add_argument('-big_endian', required=False, action='store_true', help="Whether the architecture is big endian or not")
parser.add_argument('-finder_type', type=str, default="mem", help='The type of gadget finder (memory, file)')
parser.add_argument('-o', type=str, default=None, help='File to write the gadgets to')
parser.add_argument('-parser_type', type=str, default="cle", help='The type of file parser (cle, pyelf, radare)')
parser.add_argument('-v', required=False, action='store_true', help='Verbose mode')
parser.add_argument('-validate', required=False, action='store_true', help='Validate gadgets with z3')
args = parser.parse_args()

finder_type = factories.get_finder_from_name(args.finder_type)
logging_level = logging.DEBUG if args.v else logging.WARNING
arch = archinfo.arch_from_id(args.arch, 'Iend_BE' if args.big_endian else 'Iend_LE')
finder = finder_type(args.filename, arch, 0, logging_level, args.parser_type)
gadget_list = finder.find_gadgets(args.validate)

if args.o == None:
  for gadget in gadget_list.foreach():
    print gadget
else:
  fd = open(args.o, "w")
  fd.write(gadget_list.to_string())
  fd.close()

