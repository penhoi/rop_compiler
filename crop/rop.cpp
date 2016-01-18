#include <stdio.h>
#include <string>

#include "finder.h"

int main (int argc, char** argv) {
  Finder * finder;
  std::string arch = "x86-rreil";
  if(argc < 2) {
    printf("Usage: rop filename <arch>\n");
    return 1;
  }
  if(argc > 2)
    arch = argv[2];

  finder = new Finder(arch);
  finder->find_gadgets(argv[1], 0);

  delete finder;
  return 0;
}

