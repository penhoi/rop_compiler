#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>

int unused() {
  printf("/bin/sh");
  printf("%p\n",system);

  //Add some useful gadgets
  asm volatile("\
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
pop r9; \
ret; \
mov [rsi], rdi; \
ret; \
");
}

int main(int argc, char ** argv) {
  char buffer[512];
  printf("buffer:%p\n",buffer);
  gets(buffer);
  return 0;
}
