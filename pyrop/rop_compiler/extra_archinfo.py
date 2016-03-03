# This file contains some architecture specific information that pyvex doesn't include
import collections

"""Registers reported by pyvex that we don't care to look for, per architecture"""
IGNORED_REGISTERS = collections.defaultdict(list, {
  "X86"   : ['bp', 'cc_dep1', 'cc_dep2', 'cc_ndep', 'cc_op', 'cs', 'd', 'ds', 'es', 'fc3210', 'fpround', 'fpu_regs',
             'fpu_t0', 'fpu_t1', 'fpu_t2', 'fpu_t3', 'fpu_t4', 'fpu_t5', 'fpu_t6', 'fpu_t7', 'fpu_tags', 'fs', 'ftop', 'gdt',
             'gs', 'id', 'ldt', 'mm0', 'mm1', 'mm2', 'mm3', 'mm4', 'mm5', 'mm6', 'mm7', 'ss', 'sseround', 'st0', 'st1',
             'st2', 'st3', 'st4', 'st5', 'st6', 'st7', 'xmm0', 'xmm1', 'xmm2', 'xmm3', 'xmm4', 'xmm5', 'xmm6', 'xmm7'],
  "AMD64" : [ "cc_dep1", "cc_dep2", "cc_ndep", "cc_op", "d", "fpround", "fs", "sseround"  ]
})

func_calling_convention = collections.defaultdict(list, {
  "AMD64"  : ["rdi", "rsi", "rdx", "rcx", "r8", "r9"],
  "ARMEL"  : ["r0", "r1", "r2", "r3"],
  "MIPS32" : ["a0", "a1", "a2", "a3"],
  "MIPS64" : ["a0", "a1", "a2", "a3"],
  "PPC32"  : ["r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10"],
  "PPC64"  : ["r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10"],
})

MPROTECT_SYSCALL = { "AMD64" : 10 }

syscall_calling_convention = {
  "AMD64" : [ "rdi", "rsi", "rdx", "r10", "r8", "r9" ]
}

# Architectures which pyvex adds a constraint to ensure any new IPs are aligned (i.e. they mask all IP values before assigning to the IP register)
ALIGNED_ARCHS = ['PPC32']

# Architectures which pyvex ends before the end of a block on.  For whatever reason, the last address translated may not be the
# last one that pyvex was given and not the end of a block.  For these architectures we must work around this by using multiple
# translation calls.
ENDS_EARLY_ARCHS = ['MIPS32']

