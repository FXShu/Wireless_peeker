CC=gcc
LIBS_c=
OBJS= 

OBJS += main.o 
OBJS += arp.o
OBJS += sniffer.o
OBJS += packet.o
OBJS += getif.o
OBJS += print.o
OBJS_t = print.o packet.o test.o 
LIBS_c += -lnet
LIBS_c += -lpcap
LIBS_c += -lpthread
LIBS_t = -lpcap

MITM : $(OBJS)
	$(CC) -o MITM $(OBJS) $(LIBS_c)

test : $(OBJS_t)
	$(CC) -o test $(OBJS_t) $(LIBS_t)

main.o: main.c
	$(CC) -c main.c 

arp.o: arp.c arp.h
	$(CC) -c arp.c

sniffer.o: sniffer.c sniffer.h
	$(CC) -c sniffer.c 

packet.o: packet.h packet.c
	$(CC) -c packet.c

getif.o: getif.h getif.c
	$(CC) -c getif.c 

print.o: print.h print.c
	$(CC) -c print.c

test.o : test.c
	$(CC) -c test.c

clean:
	rm MITM $(OBJS) 
clean_test :
	rm test $(OBJS_t)
