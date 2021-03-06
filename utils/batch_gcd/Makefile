CC=g++

CFLAGS=-Wall -Wextra -pedantic -march=native -O3 -flto
LIBS=-lgmp -lpthread

main: batch_gcd

batch_gcd: batch_gcd.o
	$(CC) $(CFLAGS) -o batch_gcd batch_gcd.o -Bdynamic $(LIBS)

batch_gcd.o: batch_gcd.cc
	$(CC) $(CFLAGS) -c batch_gcd.cc

clean:
	rm -f batch_gcd
	rm -f *.o
	rm -f *~
	rm -f \#*
