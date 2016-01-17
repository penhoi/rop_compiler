CPPFLAGS=-std=c++11 -ggdb3 -g -Wall -Iinclude/
LIBS=-lbfd -lcppgdsl
CPP=clang++

SRC=finder.cpp

all: ropme 

ropme:
	$(CPP) $(CPPFLAGS) $(SRC) rop.cpp -o ropme $(LIBS)

clean:
	rm -f ropme
