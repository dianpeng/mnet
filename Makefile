FAGS=-O3
CC=g++
all: libmnet

mnet: mnet.h mnet.cc
	$(CC) -c -g $(FLAGS) mnet.cc

libmnet: mnet
	ar rcs libmnet.a mnet.o
clean:
	rm -f *.o *a

