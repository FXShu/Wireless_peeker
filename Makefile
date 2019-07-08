CC=gcc 
CFLAGS = -g -std=gnu99 -pedantic 
CFLAGS += -I$(abspath ../src)
CFLAGS += -I$(abspath ../src/utils)
LIBS_c=
OBJS= 

OBJS += main.o arp.o sniffer.o packet.o getif.o print.o hashtab.o parse.o
OBJS_t = print.o packet.o test.o sniffer.o

LIBS_c += -lnet
LIBS_c += -lpcap
LIBS_c += -lpthread
LIBS_t = -lpcap

BINALL=MITM
ALL = $(BINALL)
all: install $(ALL)

MITM : $(OBJS)	
	$(CC) $(CFLAGS) $(OBJS) -o MITM  $(LIBS_c)

install: 
	$(MAKE) -C src

test : $(OBJS_t)
	$(CC) $(CFLAGS) -o test $(OBJS_t) $(LIBS_t)

main.o: main.c
	$(CC) $(CFLAGS) -c main.c 

arp.o: arp.c arp.h
	$(CC) $(CFLAGS) -c arp.c

sniffer.o: sniffer.c sniffer.h
	$(CC) $(CFLAGS) -c sniffer.c 

packet.o: packet.h packet.c
	$(CC) $(CFLAGS) -c packet.c

getif.o: getif.h getif.c
	$(CC) $(CFLAGS) -c getif.c 

print.o: print.h print.c
	$(CC) $(CFLAGS) -c print.c

hashtab.o: hashtab.c hashtab.h
	$(CC) $(CFLAGS) -c hashtab.c

parse.o: parse.c parse.h
	$(CC) $(CFLAGS) -c parse.c

test.o : test.c
	$(CC) $(CFLAGS) -c test.c

clean:
	rm MITM *.o 
	$(MAKE) -C src clean
clean_test :
	rm test $(OBJS_t)
	$(MAKE) -C src clean
