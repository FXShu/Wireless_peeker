CC=gcc
CFLAGS = -g
LIBS_c=
OBJS= 

OBJS += main.o arp.o sniffer.o packet.o getif.o print.o hashtab.o parse.o
OBJS_t = print.o packet.o test.o sniffer.o
LIBS_c += -lnet
LIBS_c += -lpcap
LIBS_c += -lpthread
LIBS_t = -lpcap

MITM : $(OBJS) 
	$(CC) $(OBJS) -g -o MITM  $(LIBS_c)

test : $(OBJS_t)
	$(CC) -o test $(OBJS_t) $(LIBS_t)

main.o: main.c
	$(CC) -g -c main.c 

arp.o: arp.c arp.h
	$(CC) -g -c arp.c

sniffer.o: sniffer.c sniffer.h
	$(CC) -g -c sniffer.c 

packet.o: packet.h packet.c
	$(CC) -g -c packet.c

getif.o: getif.h getif.c
	$(CC) -g -c getif.c 

print.o: print.h print.c
	$(CC) -g -c print.c

hashtab.o: hashtab.c hashtab.h
	$(CC) -g -c hashtab.c

parse.o: parse.c parse.h
	$(CC) -g -c parse.c

test.o : test.c
	$(CC) -g -c test.c

clean:
	rm MITM *.o 
clean_test :
	rm test $(OBJS_t)
