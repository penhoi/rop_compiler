This directory contains the code for a ROP compiler that uses pyvex to support multiple architectures.  The ROP compiler is
an attempt to make a usable, open source, multi-architecture ROP compiler.  It is based on the ROP compiler discussed in the paper
["Q: Exploit Hardening Made Easy"](https://users.ece.cmu.edu/~ejschwar/papers/usenix11.pdf) by Schwartz et al.

This ROP compiler is/does not:

0. complete
1. foolproof
2. allow for turing complete computation in ROP gadgets (sorry iPhone/grsecurity hackers)
3. bug free (please open issues if/when you find bugs)

However, it is/does:

0. provide a few built-in mechanisms for spawning a shell
1. usable for most simple cases
2. open source
3. multi-architecture (tested on x86, x64, ARM32, PPC32, and MIPS32; but probably works on all the architectures supported by pyvex)
4. use semantic based searching to find gadgets that syntax based gadget finders might miss
5. combine gadgets to synthesize missing ones

In short, this will not put an end to manual ROP compilation.  However, for the simple cases, it can generate useful ROP chains.
In the future, I will be working to expand its usefulness.  See the TODO file to see what's planned (eventually).  If something is
not in the list that you want, add an issue for it and I'll add it (or a pull request implementing it).

The documentation is lacking at the moment, but there are a number of examples.  For the most part, you will just want to use the ropme.rop method.

## Dependencies:

Required:

* [pyvex](https://github.com/angr/pyvex)
* [archinfo](https://github.com/angr/archinfo)
* [cle](https://github.com/angr/cle)
* [z3 with python bindings](https://github.com/Z3Prover/z3)

Optional:

* [pwntools](https://github.com/Gallopsled/pwntools)
  * Pwntools is a set of python libraries that ease the process of exploit development (process wrappers, gdb support, etc).
  * It's only needed to run the example scripts and test suite or as an alternative to cle.  Besides that it's not used in the actual pyrop library.
  * FYI, the version in pip is old and you should install it from github.
* [pyelftools](https://github.com/eliben/pyelftools)
  * This package is only used as an alternative to cle, and is optional
  * FYI, the pyelftools package in pip repos is old
* [radare2](https://github.com/radare/radare2)
  * This package is only used as an alternative to cle, and is optional
