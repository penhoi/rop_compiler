#include <stdio.h>
#include <dlfcn.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/mman.h>

char big_buffer[1024];
void * libc;

int main(int argc, char ** argv) {
  char buffer[512];
  libc = dlopen("libc.so.6", RTLD_LAZY | RTLD_GLOBAL);
  printf("puts:%p\n", dlsym(libc, "puts"));
  read(0, big_buffer, sizeof(big_buffer));
  strcpy(buffer, big_buffer);
  return 0;
}

