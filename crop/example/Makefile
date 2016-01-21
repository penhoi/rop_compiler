X86_ASSEMBLY_FILES=$(shell ls x86_*.s)
X86_TARGETS = $(shell echo $(X86_ASSEMBLY_FILES) | sed 's/\.s//g')
MIPS_ASSEMBLY_FILES=$(shell ls mips_*.s)
MIPS_TARGETS = $(shell echo $(MIPS_ASSEMBLY_FILES) | sed 's/\.s//g')
PPC_ASSEMBLY_FILES=$(shell ls ppc_*.s)
PPC_TARGETS = $(shell echo $(PPC_ASSEMBLY_FILES) | sed 's/\.s//g')
ARM_ASSEMBLY_FILES=$(shell ls arm_*.s)
ARM_TARGETS = $(shell echo $(ARM_ASSEMBLY_FILES) | sed 's/\.s//g')
CFLAGS = -nostdlib -Ttext 0x800000

bof:
	gcc -g -fno-stack-protector bof.c -o bof -masm=intel

$(X86_TARGETS):
	gcc $@.s -o $@.o -masm=intel $(CFLAGS)
	objcopy -O binary $@.o $@

$(MIPS_TARGETS):
	mips-elf-gcc $@.s -o $@.o $(CFLAGS)
	mips-elf-objcopy -O binary $@.o $@

$(PPC_TARGETS):
	powerpc-elf-gcc $@.s -o $@.o $(CFLAGS)
	powerpc-elf-objcopy -O binary $@.o $@

$(ARM_TARGETS):
	arm-linux-gnueabi-gcc $@.s -o $@.o $(CFLAGS)
	arm-linux-gnueabi-objcopy -O binary $@.o $@

clean:
	rm -f *.o $(X86_TARGETS) $(MIPS_TARGETS)

