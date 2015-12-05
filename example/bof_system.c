#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>

int unused() {
  printf("%p: sleep 1000",system);

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
");

  exit(0);
}

int main(int argc, char ** argv) {
  char buffer[512];
  if(argc < 2) {
    printf("Usage: bof length_to_read\n");
    return 1;
  }
  printf("buffer:%p\n",buffer);
  read(0, buffer, atoi(argv[1]));
  return 0;
}
