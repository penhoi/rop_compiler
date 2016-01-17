ASSEMBLY_FILES=$(shell ls *.s)
TARGETS = $(shell echo $(ASSEMBLY_FILES) | sed 's/\.s//g')

bof:
	gcc -g -fno-stack-protector bof.c -o bof -masm=intel

$(TARGETS):
	as $@.s -o $@.o
	objcopy -O binary $@.o $@

clean:
	rm -f *.o $(TARGETS)

