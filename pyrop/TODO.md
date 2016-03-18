This file contains a list of TODO items (not necessarily in priority order) for the python based ROP compiler.

* Documentation
* Blacklisting of gadgets (or detection of bad ones)
  * complexcalc rop gadget script
* Blacklisting of bytes (i.e. avoid NULL bytes for when overflowing strcpy)
* A generic script that will try to spawn a shell (i.e. so we don't need to code a script for each binary/technique)
* Windows support
* Stack Migration support
* Integrate with pwntools/binjitsu
* ARM thumb mode
* Use plex (python lexer) and ply (python yacc) to allow for running arbitrary code in ROP gadgets (i.e. full compiling rather than just spawning a shell)
* Determine some way to know when we have *enough* gadgets. This will let us quit searching early, and build the chain much faster.
* Implement more combination gadgets to allow for creation of chains when desired gadgets cannot be found
* Use the multiprocessing module to speed up gadget finding
