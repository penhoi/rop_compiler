#!/usr/bin/env python

from setuptools import setup

name = "pyrop"
package_dir  = "rop_compiler"
version = "0.1"
description = """
This tool searches for gadgets in binaries and tries to combine them into chains to help achieve code execution. 
pyrop is multi-architecture and has been tested on x86, x64, ARM, PowerPC, and MIPS architectures.
""".strip()

setup(
    name             = name,
    version          = version,
    description      = description,
    packages         = ['rop_compiler'],
    author           = "jeffball",
    author_email     = "jeffball@dc949.org",
    install_requires = ['pyvex', 'archinfo'],
    url              = "https://github.com/jeffball55/rop_compiler",
    classifiers      = [
        'Topic :: Security',
        'Environment :: Console',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 2.7',
        'Intended Audience :: Developers'
    ]
)
