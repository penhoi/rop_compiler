This repository contains my attempts at making a useful, open source, multi-architecture ROP compiler.
To that end, there are two versions:

1. A python-based ROP compiler built on pyvex and cle from angr.  This one works to some extent.  The source for this is in the
pyrop/ directory.
2. A C-based ROP compiler built on GDSL and libbfd.  This one is still very much in the concept phase.  The source for this is
in the crop/ directory.

If you're looking for a working ROP compiler, you want (1).  At some point in the future, I may see fit to finish (2).
