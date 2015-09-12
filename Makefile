CFLAGS = "-DPI_SIZE=64"

all: test

clean:
	rm -f main pi-cipher.o
	
test: main

main: main.c pi-cipher.o pi64cipher128v1/ref/encrypt.c
	$(CC) $(CFLAGS) -o $@ $^
	
pi-cipher.o: pi-cipher.c pi-cipher.h pi64_parameter.h
	$(CC) $(CFLAGS) -c -o $@ $<