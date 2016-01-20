.global _start
_start:

lw $ra, 0x10($sp)
lw $s0, 0x08($sp)
jr $ra
