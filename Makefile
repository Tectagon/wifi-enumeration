CC=gcc
CFLAGS=-g -Wall -Wextra

all: main

main: main.o
	$(CC) $(CFLAGS) -o main main.o -lpcap

main.o: main.c 
	$(CC) $(CFLAGS) -c main.c


clean: cleanobject
	rm main

cleanobject:
	rm *.o