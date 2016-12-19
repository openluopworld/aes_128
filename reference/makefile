IDIR=./../include
CC=gcc
CFLAGS=-Wall -I$(IDIR)

ref_aes.out: aes.o ./../test/main.o
	$(CC) -o $@ $^ $(CFLAGS)

clean:
	rm -f ref_aes.out
	rm -f *.o ./../test/main.o
	rm -f *~
