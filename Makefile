CC=gcc
LIBS_c=
OBJS= 

OBJS += main.o
OBJS += arp.o
OBJS += sniffer.o
OBJS += packet.o

LIBS_c += -lnet
LIBS_c += -lpcap
LIBS_c += -lpthread

MITM : $(OBJS)
	$(CC) -o MITM $(OBJS) $(LIBS_c)

main.o: main.c
	$(CC) -c main.c 

arp.o: arp.c arp.h
	$(CC) -c arp.c

sniffer.o: sniffer.c sniffer.h
	$(CC) -c sniffer.c 

packet.o: packet.h packet.c
	$(CC) -c packet.c

clean:
	rm MITM main.o arp.o sniffer.o
