#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <vector>
#include <string>

#include <bfd.h>

#include "finder.h"
#include "classifier.h"

#define min(a, b) ({__typeof__(a) _a = (a); __typeof__(b) _b = (b); _a < _b ? _a : _b;})

Finder::Finder(std::string architecture)
{
  arch = architecture;
}

unsigned char * Finder::get_section_code(asection * sec, int fd)
{
  size_t len, temp;
  unsigned char * code_buffer = (unsigned char *)malloc(sec->size);
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

std::vector<Gadget *> Finder::find_gadgets(char * filename, unsigned long long base_address)
{
	bfd * ibfd;
  struct bfd_section * sec;
  int fd, gadget_size;
  unsigned char * code_buffer;
  unsigned long long sec_address, gadget_address, offset;

  std::vector<Gadget *> gadgets, temp;
  Classifier classifier(arch);

  bfd_init();

  fd = open(filename, O_RDONLY);
  if(fd < 0)
    return gadgets;

  ibfd = bfd_openr(filename, NULL);
	if(ibfd == NULL)
		return gadgets;

  if(!bfd_check_format(ibfd, bfd_object))
    return gadgets;

  for (sec = ibfd->sections; sec != NULL; sec = sec->next)
  {
    if(!(sec->flags & SEC_CODE)) //We only care about the executable sections
      continue;

    sec_address = base_address + sec->vma;
    if(sec_address == 0)
      printf("No base address given for library or PIE executable.  Addresses may be wrong\n");
      
    printf("Looking for gadgets in section %s (Address 0x%lx, Size 0x%lx)\n", sec->name, sec->vma, sec->size);
    code_buffer = get_section_code(sec, fd);
    if(!code_buffer)
      continue;

    //code is in code_buffer, sec->size bytes in size, at address sec_address
    for(offset = 0; offset < sec->size; offset++) {
      gadget_address = sec_address + offset;
      printf("Looking for gadgets at address 0x%llx\n", gadget_address);

      gadget_size = min(sec->size - offset, MAX_GADGET_SIZE);
      temp = classifier.create_gadgets_from_instructions(code_buffer + offset, gadget_size, gadget_address);
      printf("Found %zu gadgets at address 0x%llx\n", temp.size(), gadget_address);
      gadgets.insert(temp.end(), temp.begin(), temp.end());
      printf("\n");
    }
    
    free(code_buffer);
  }

  printf("Finished %s\n", filename);
	return gadgets;
}
