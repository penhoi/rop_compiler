#include <stdio.h>
#include <stdlib.h>

int main(int argc, char ** argv) {
  char buffer[512];
  if(argc < 2) {
    printf("Usage: bof length_to_read\n");
    return 1;
  }
  printf("exit:%p\n",exit);
  read(0, buffer, atoi(argv[1]));
  return 0;
}
