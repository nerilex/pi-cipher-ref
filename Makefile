PI_SIZE = 16


CFLAGS = "-DPI_SIZE=$(PI_SIZE)"

all: test

clean:
	rm -f main pi-cipher.o
	
test: main

main: main.c pi-cipher.o pi$(PI_SIZE)cipher128v1/ref/encrypt.c
	$(CC) $(CFLAGS) -o $@ $^
	
pi-cipher.o: pi-cipher.c pi-cipher.h pi$(PI_SIZE)_parameter.h
	$(CC) $(CFLAGS) -c -o $@ $<