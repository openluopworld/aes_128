CC=gcc
CFLAGS=-Wall -Os

aes.out: aes.o main.o
	$(CC) -o $@ $^ $(CFLAGS)

clean:
	rm -f aes.out
	rm -f *.o
