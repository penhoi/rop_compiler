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

unsigned char * get_section_code(asection * sec, int fd)
{
  ssize_t len, temp;
  unsigned char * code_buffer = malloc(sec->size);
  if(!code_buffer)
    return NULL;

  lseek(fd, sec->filepos, SEEK_SET);

  len = 0;
  while(len < sec->size)
  {
    temp = read(fd, code_buffer+len, sec->size - len);
    if(temp > 0)
      len += temp;
  }

  return code_buffer;
}

gadgets * find_gadgets(char * filename, unsigned long long base_address)
{
	bfd * ibfd;
  gadgets * gadget = NULL;
  struct bfd_section * sec;
  int fd;
  unsigned char * code_buffer;
  unsigned long long sec_address, gadget_address;
  long long i, j, begin;
  state_t s = gdsl_init();

  bfd_init();

  fd = open(filename, O_RDONLY);
  if(fd < 0)
    return NULL;

  ibfd = bfd_openr(filename, NULL);
	if(ibfd == NULL)
		return NULL;

  if(!bfd_check_format(ibfd, bfd_object))
    return NULL;

  for (sec = ibfd->sections; sec != NULL; sec = sec->next)
  {
    if(!(sec->flags & SEC_CODE)) //We only care about the executable sections
      continue;

    sec_address = base_address + sec->vma;
    if(sec_address == 0)
      printf("No base address given for library or PIE executable.  Addresses may be wrong");
      
    printf("Looking for gadgets in section %s (Address 0x%x, Size 0x%x)\n", sec->name, sec->vma, sec->size);
    code_buffer = get_section_code(sec, fd);
    if(!code_buffer)
      continue;

    gdsl_set_code(s, code_buffer, sec->size, sec_address);
    for(i = 0; i < sec->size; i++) {
      gadget_address = sec_address + i;
      gdsl_seek(s, gadget_address);

      while(gdsl_get_ip(s)- sec_address < MAX_GADGET_SIZE) {
        if (setjmp(*gdsl_err_tgt(s)) != 0) {
          fprintf(stdout,"exception at address 0x%lx: %s", gdsl_get_ip(s), gdsl_get_error_message(s));
          if(gdsl_seek(s,gdsl_get_ip(s)+1))
            break;
        }

        opt_result_t block = gdsl_decode_translate_block_optimized(s, 0, gdsl_int_max(s), 0);

        obj_t res = gdsl_rreil_pretty(s,block->rreil);
        string_t str = gdsl_merge_rope(s,res);
        printf("0x%016lx:\n",gdsl_get_ip(s));
        fputs(str,stdout);
      }
      gdsl_reset_heap(s);
    }
    
    free(code_buffer);
  }

  printf("Finished %s\n", filename);
	return gadget;

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
