CC=gcc
CFLAGS=-g -Wall -Wextra

HDEP=header/
SDEP=service/

all: probe

probe: probe.o setup.o
	$(CC) $(CFLAGS) -o probe probe.o setup.o -lpcap

probe.o: probe.c $(HDEP)probe.h 
	$(CC) $(CFLAGS) -c probe.c

setup.o: $(SDEP)setup.c $(HDEP)setup.h $(HDEP)error.h
	$(CC) $(CFLAGS) -c $(SDEP)setup.c

clean:
	rm *.o probe