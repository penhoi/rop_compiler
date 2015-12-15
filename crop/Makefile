CFLAGS=--std=c99
SRC=finder.c

x86_rop:
	$(CC) $(CFLAGS) $(SRC) rop.c -o x86_rop -lgdsl-x86-rreil

run:
	echo LD_PRELOAD=/usr/local/lib/libgdsl-x86-rreil.so ./x86_rop --help

clean:
	rm x86_rop
