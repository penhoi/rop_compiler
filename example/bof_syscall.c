#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

int unused() {
  printf("%p\n",syscall);

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
