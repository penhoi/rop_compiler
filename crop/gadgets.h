#ifndef __GADGETS__H_
#define __GADGETS__H_

//One gadget
struct gadget
{
  unsigned long long address;
  struct inst * insts;
  struct gadget * next;
};
typedef struct gadget gadget;

//One instruction
struct inst
{
  opt_result_t block;
  struct inst * next;
};
typedef struct inst inst;


#endif // __GADGETS__H_
