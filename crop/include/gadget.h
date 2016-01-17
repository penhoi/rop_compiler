#ifndef __GADGET__H_
#define __GADGET__H_

#include "operand.h"

class Gadget
{
  public:
    Gadget(std::vector<Operand> operand, Operand output, std::vector<unsigned long long> parameters,
      unsigned long long stack_offset, unsigned long long ip_in_stack_offset);
};

#endif // __GADGET__H_
