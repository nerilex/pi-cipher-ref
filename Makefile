CFLAGS = "-DPI_SIZE=32"

all: test

test: main

main: main.c pi-cipher.o pi32cipher128v1/ref/encrypt.c
	$(CC) $(CFLAGS) -o $@ $^
	
pi-cipher.o: pi-cipher.c pi-cipher.h pi32_parameter.h
	$(CC) $(CFLAGS) -c -o $@ $<