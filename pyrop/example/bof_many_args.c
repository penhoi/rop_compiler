#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void unused()
{
#ifdef __amd64__
  asm volatile("\
pop rdi; \
ret; \
pop rsi; \
ret; \
pop rdx; \
ret; \
pop rcx; \
ret; \
pop r8; \
ret; \
pop r9; \
ret; \
" : : );
#endif
}

void callme(int a, int b, int c, int d, int e, int f, int g, int h)
{
  printf("Called with (%d,%d,%d,%d,%d,%d,%d,%d)\n", a, b, c, d, e, f, g, h);
  exit(55);
}

int main(int argc, char ** argv) {
  char buffer[512];
  if(argc < 2) {
    printf("Usage: bof length_to_read\n");
    return 1;
  }
  read(0, buffer, atoi(argv[1]));
  return 0;
}
