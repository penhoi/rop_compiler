#ifndef __FINDER__H_
#define __FINDER__H_

#define MAX_GADGET_SIZE 10

#include <bfd.h>

#include <vector>

#include "gadget.h"

class Finder
{
  private:
    unsigned char * get_section_code(asection * sec, int fd);

  public:
    std::vector<Gadget *> find_gadgets(char * filename, unsigned long long base_address);
};

#endif // __FINDER__H_
