#include <string.h>
#include <stdio.h>
#include <limits.h>
#include <bfd.h>
#include <gdsl-x86-rreil.h>

#include "finder.h"

void find_gagdets(char * filename)
{
	bfd * ibfd;
  ibfd = bfd_openr(output_filename, NULL);
	if(ibfd == NULL) {
		printf("Failed opening it\n");
  }
	else
		printf("Opened it\n");

	return;

/*


  size_t buf_size = BUF_SIZE;
  FILE* file = NULL;
  int_t decode_options = 0;
  int_t optimization_options = 0;
  int_t run_translate = 0;
  int_t translate_options = 0;
  size_t base_address = 0;
  size_t start_address = 0;
  int print_addr = 0;
  obj_t config;
  state_t s = gdsl_init();
  long long alloc_size,alloc_no,alloc_max;

	printf("Looking for gadgets in %s\n", filename);


  // initialize the GDSL program
  gdsl_set_code(s, blob, buf_size, base_address);
  gdsl_seek(s, start_address);

  alloc_size = 0;
  alloc_no = 0;
  alloc_max = 0;

  while (gdsl_get_ip(s)-base_address<buf_size) {
    size_t size;
    if (setjmp(*gdsl_err_tgt(s))==0) {
      if (run_translate) {
        opt_result_t block = gdsl_decode_translate_block_optimized(s,
          decode_options,
          gdsl_int_max(s),
          optimization_options);
        obj_t res = gdsl_rreil_pretty(s,block->rreil);
        string_t str = gdsl_merge_rope(s,res);
        if (print_addr) printf("0x%016lx:\n",gdsl_get_ip(s));
        fputs(str,stdout);
      } else {
        obj_t instr = gdsl_decode(s, decode_options);
        obj_t res = gdsl_pretty(s,instr);
        string_t str = gdsl_merge_rope(s,res);
        if (print_addr) printf("%016lx ",gdsl_get_ip(s));
        fputs(str,stdout);
      }
    } else {
      fprintf(stdout,"exception at address 0x%lx: %s", gdsl_get_ip(s), gdsl_get_error_message(s));
    //  size_t step = (s->token_addr_inv>0 ? (size_t) s->token_addr_inv+1 : 1u);
      //if(gdsl_seek(s,gdsl_get_ip(s)+step))
				break;
    }
    fputs("\n",stdout);
    size = gdsl_heap_residency(s);
    alloc_size += size;
    alloc_no++;
    if (size>alloc_max) alloc_max = size;
    gdsl_reset_heap(s);
  }
  fprintf(stderr, "heap: no: %lli mem: %lli max: %lli\n", alloc_no, alloc_size, alloc_max);
  gdsl_destroy(s);
  return 0;
*/
}
