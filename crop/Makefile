CPPFLAGS=-std=c++11 -ggdb3 -g -Wall -Iinclude/
LIBS=-lbfd -lcppgdsl
CPP=clang++

SRC=finder.cpp gadget.cpp operand.cpp classifier.cpp
OBJ=$(SRC:.cpp=.o)

all: ropme 

%.o: %.cpp
	$(CPP) $(CPPFLAGS) -c -o $@ $<

ropme: $(OBJ)
	$(CPP) $(CPPFLAGS) $(LIBS) $(OBJ) rop.cpp -o ropme

clean:
	rm -f ropme *.o
