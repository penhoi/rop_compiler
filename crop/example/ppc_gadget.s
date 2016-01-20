.global _start
_start:

lwz 31, 0x8(1)
lwz 0,  0x4(1)
mtlr 0
blr
