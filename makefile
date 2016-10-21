CC=gcc
CFLAGS=-Wall

aes.out: main.o aes.o
	$(CC) -o $@ $^ $(CFLAGS)

clean:
	rm -f aes.out
	rm -f *.o
	rm -f *~
