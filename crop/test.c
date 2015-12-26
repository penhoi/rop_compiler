#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <bfd.h>
#include <gdsl-x86-rreil.h>

#include "finder.h"
#include "gadgets.h"

#define min(a, b) ({__typeof__(a) _a = (a); __typeof__(b) _b = (b); _a < _b ? _a : _b;})

gadget * find_gadget(state_t s, unsigned long long sec_address, unsigned long long offset, int size)
{
  unsigned long long gadget_address = sec_address + offset;
  int gadget_size;
  gdsl_seek(s, gadget_address);

  printf("Looking for gadgets at address 0x%lx\n", gdsl_get_ip(s));

  while(gdsl_get_ip(s)- sec_address < MAX_GADGET_SIZE) {
    printf("Start at address 0x%lx\n", gdsl_get_ip(s));
    if (setjmp(*gdsl_err_tgt(s)) != 0) {
      fprintf(stdout,"exception at address 0x%lx: %s\n", gdsl_get_ip(s), gdsl_get_error_message(s));
      if(gdsl_seek(s,gdsl_get_ip(s)+1))
        break;
    }
    printf("After at address 0x%lx\n", gdsl_get_ip(s));

    gadget_size = min(size - offset, MAX_GADGET_SIZE);
    opt_result_t block = gdsl_decode_translate_block_optimized(s, 0, gadget_size, 0);
    obj_t res = gdsl_rreil_pretty(s,block->rreil);
    string_t str = gdsl_merge_rope(s,res);
    printf("0x%016lx:\n%s\n",gdsl_get_ip(s), str);

    // obj_t instr = gdsl_decode(s, gadget_size);
    // obj_t res2 = gdsl_pretty(s,instr);
    // string_t strz = gdsl_merge_rope(s,res2);
    // printf("0x%016lx:\n%s\n",gdsl_get_ip(s), strz);


    printf("End at address 0x%lx\n", gdsl_get_ip(s));
  }
  return NULL;
}

int main(int argc, char ** argv) 
{
  unsigned char * code_buffer;
  unsigned long long sec_address;
  int i, size, fd;
  state_t s = gdsl_init();
  gadget * gadgets, * current = NULL;

  if(argc < 2)
  {
    printf("Usage: rop <filename>\n");
    return 1;
  }
  fd = open(argv[1], O_RDONLY);
  if(fd < 0)
    return 2;
  
  code_buffer = malloc(1024);
  size = read(fd, code_buffer, 1024);
  sec_address = 0; 

  gdsl_set_code(s, code_buffer, size, sec_address);
  for(i = 0; i < size; i++)
  {
    gadget * found = find_gadget(s, sec_address, i, size);
    if(found) 
    {
      found->next = NULL;
      if(!gadgets)
        gadgets = current = found;
      else
      {
        current->next = found;
        current = found;
      }
    }
  }

  gdsl_reset_heap(s);
  gdsl_destroy(s);
  free(code_buffer);
	return 0;
}

