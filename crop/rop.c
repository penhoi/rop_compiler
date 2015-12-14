/* vim:set ts=2:set sw=2:set expandtab: */
/* Auto-generated file. DO NOT EDIT. */

#include "gdsl-x86-rreil.h"
#include <string.h>
#include <stdio.h>
#include <limits.h>

#define HAVE_TRANS
#define HAVE_DECODE

#define BUF_SIZE 32*1024*1024
static unsigned char blob[BUF_SIZE];

int readNum(char* str, size_t* res) {
  size_t mult = 10;
  *res = 0;
  while (*str) {
    char c = *str;
    if (c=='x') mult=16; else
      if ((c>='0') && (c<='9')) *res=*res*mult+(size_t) (c-'0'); else
        if ((c>='a') && (c<='f')) *res=*res*mult+10+(size_t) (c-'a'); else
          if ((c>='A') && (c<='F')) *res=*res*mult+10+(size_t) (c-'A'); else
            return 1;
    str++;
  }
  return 0;
}

int main (int argc, char** argv) {
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
  
  /* read command line parameters */
  int i;
  for(i=1; i<argc; i++) {
    char* arg = argv[i];
    if (strncmp(arg,"--",2)) {
      file = fopen(arg,"r");
      if (file==NULL) {
        printf("file '%s' not found, please run %s --help for usage\n", arg, argv[0]);
        return 1;
      }
    } else {
      arg+=2;
      for (config = gdsl_decoder_config(s); gdsl_has_conf(s,config);
        config = gdsl_conf_next(s,config))
        if (strcmp(arg,gdsl_conf_short(s,config))==0) {
          decode_options |= gdsl_conf_data(s,config);
          break;
        }
      if (gdsl_has_conf(s,config)) continue;
      for (config = gdsl_optimization_config(s); gdsl_has_conf(s,config);
        config = gdsl_conf_next(s,config))
        if (strcmp(arg,gdsl_conf_short(s,config))==0) {
          optimization_options |= gdsl_conf_data(s,config);
          break;
        }
      if (gdsl_has_conf(s,config)) continue;
      if (strncmp(arg,"base=",5)==0) {
        int res=readNum(arg+5,&base_address);
        print_addr=1;
        if (res==0) continue;
      }
      if (strncmp(arg,"start=",6)==0) {
        int res=readNum(arg+6,&start_address);
        if (res==0) continue;
      }
      if (strcmp(arg,"trans")==0) {
        run_translate = 1;
        continue;
      }
      fprintf(stderr,
        "Command line argument `%s' not recognized. Usage:\n"
        "\t%s [options] filename\nwhere\n"
        "  --trans               translate to semantics\n"
        "  --base=addr           print addresses relative to addr\n"
        "  --start=addr          decode starting from addr\n", argv[i], argv[0]);
      for (config = gdsl_decoder_config(s); gdsl_has_conf(s,config);
        config = gdsl_conf_next(s,config))
        fprintf(stderr,"  --%s\t\t%s\n",
          gdsl_conf_short(s,config), gdsl_conf_long(s,config));
      for (config = gdsl_optimization_config(s); gdsl_has_conf(s,config);
        config = gdsl_conf_next(s,config))
        fprintf(stderr,"  --%s\t\t%s\n",
          gdsl_conf_short(s,config), gdsl_conf_long(s,config));
      return 1;
    }
  }
  /* fill the buffer, either in binary from file or as sequence
     of hex bytes separated by space or newlines */
  if (file) {
    size_t bytes_read = fread(blob, 1, BUF_SIZE, file);
    if (bytes_read == 0) return 1;
    buf_size = bytes_read;
  } else {
    size_t i=0;
    int num=0;
    int digit=0;
    while (i<buf_size) {
      int x = getchar();
      if (x==EOF) buf_size = i; else
      if ((x>='0') && (x<='9')) { num=num*16+(x-'0'); digit++; } else
      if ((x>='a') && (x<='f')) { num=num*16+(10+x-'a'); digit++; } else
      if ((x>='A') && (x<='F')) { num=num*16+(10+x-'A'); digit++; } else
      if (x>' ') {
        fprintf(stderr, "invalid input; should be in hex form: '0f 0b ..'.\n");
        return 1;
      }
      if (digit==2) { blob[i] = num & 0xff; i+=1; digit=0; };
    }
  }  
  /* initialize the GDSL program */
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
}

