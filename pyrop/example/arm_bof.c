#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <string.h>

int ret, i, client_fd;
char achar;
char * buffer_ptr;

int unused() {
  printf("%p\n",mprotect);

  //Add some useful gadgets
  asm volatile("\
    pop {r0, pc}; \
    pop {r1, pc}; \
    pop {r2, pc}; \
    pop {lr, pc}; \
");
}

void setup_client_conn()
{
  int listen_fd;
  struct sockaddr_in servaddr;

  listen_fd = socket(AF_INET, SOCK_STREAM, 0);
  bzero( &servaddr, sizeof(servaddr));

  servaddr.sin_family = AF_INET;
  servaddr.sin_addr.s_addr = htons(INADDR_ANY);
  servaddr.sin_port = htons(80);

  bind(listen_fd, (struct sockaddr *) &servaddr, sizeof(servaddr));
  listen(listen_fd, 1);
  client_fd = accept(listen_fd, (struct sockaddr*) NULL, NULL);
  if(client_fd < 0) {
    printf("Couldn't get client fd\n");
    exit(3);
  }
}

int main(int argc, char ** argv) {
  char buffer[512];
  if(argc < 2) {
    printf("Usage: bof length_to_read\n");
    return 1;
  }

  setup_client_conn();
  if(client_fd < 0) {
    printf("Client connection failed\n");
    return 2;
  }

  buffer_ptr = buffer;
  write(client_fd, &buffer_ptr, sizeof(buffer_ptr));

  i = 0;
  while(1)
  {
    ret = read(client_fd, &achar, 1);
    if(ret > 0)
    {
      if(buffer[i-3] == 'J' && buffer[i-2] == 'E' && buffer[i-1] == 'F' && achar == 'F')
        break;
      buffer[i] = achar;
      i++;
    }
  }
  return 0;
}
