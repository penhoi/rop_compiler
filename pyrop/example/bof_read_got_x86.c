#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int unused() {
  //Add some useful gadgets (while working around clang's inability to deal with inline assembly)
  asm(".byte 0x5f; .byte 0xc3"); // pop edi; ret
  asm(".byte 0x5e; .byte 0xc3"); // pop esi; ret
  asm(".byte 0x58; .byte 0xc3"); // pop eax; ret
  asm(".byte 0xff; .byte 0xe0"); // jmp eax
  asm(".byte 0x8b; .byte 0x07; .byte 0xc3"); // mov eax,DWORD PTR [edi]; ret
  asm(".byte 0x01; .byte 0xf8; .byte 0xc3"); // add eax, edi; ret
  asm(".byte 0x89; .byte 0x37; .byte 0xc3"); // move DWORD PTR[edi], esi; ret
  exit(55);
}

int main(int argc, char ** argv) {
  char buffer[512];
  if(argc < 2) {
    printf("Usage: bof length_to_read\n");
    return 1;
  }
  printf("Good luck exploiting with %s in the plt.\n", "no useful functions");
  read(0, buffer, atoi(argv[1]));
  return 0;
}
