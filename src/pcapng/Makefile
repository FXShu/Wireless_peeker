all: libpcapng.a

clean:
	rm -f *~ *.o *.d *.gcno *.gcda *.gcov $(all)

intstall:
	@echo Nothing to be made



include ../lib.rules

LIB_OBJS= pcapng.o

libpcapng.a: $(LIB_OBJS)
	$(AR) crT $@ $?

-include $(OBJS:%.o=%.d)
