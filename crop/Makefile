CFLAGS=--std=c99 -g -Wall
LIBS=-lgdsl-x86-rreil -lbfd
SRC=finder.c

all: x86_rop

x86_rop:
	$(CC) $(CFLAGS) $(SRC) rop.c -o x86_rop $(LIBS)

run:
	echo LD_PRELOAD=/usr/local/lib/libgdsl-x86-rreil.so ./x86_rop --help

clean:
	rm -f x86_rop
