.global _start
_start:

ADD             SP, SP, #0x200
LDMFD           SP!, {R4-R11,PC}
