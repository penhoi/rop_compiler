#include <stdio.h>

#include "finder.h"

int main (int argc, char** argv) {
  Finder finder;
  if(argc < 2) {
    printf("Usage: rop <filename>\n");
    return 1;
  }
  finder.find_gadgets(argv[1], 0);
  return 0;
}

