all: test

test: main

main: main.c pi-cipher.o old_encrypt.c
	$(CC) -o $@ $^
	
pi-cipher.o: pi-cipher.c pi-cipher.h pi16_parameter.h
	$(CC) -c -o $@ $<