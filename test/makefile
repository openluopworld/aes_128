IDIR=./../include
CC=gcc
CFLAGS=-Wall -I$(IDIR)

aes.out: main.o aes.o
	$(CC) -o $@ $^ $(CFLAGS)

clean:
	rm -f aes.out
	rm -f *.o
	rm -f *~
