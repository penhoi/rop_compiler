#include <stdio.h>
#include <stdlib.h>

int unused() {
  //Add some useful gadgets
  asm volatile("\
pop rdi; \
pop rsi; \
ret; \
pop rdi; \
ret; \
pop rsi; \
ret; \
pop rdx; \
ret; \
pop rdx; \
ret; \
pop rcx; \
ret; \
pop r8; \
ret; \
pop rax; \
ret; \
jmp rax; \
mov rax, [rdi]; \
ret; \
add rax, rdi; \
ret; \
mov [rdi], rsi; \
ret; \
");
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
