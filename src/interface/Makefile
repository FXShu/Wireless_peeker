all: libiw.a

clean:
	rm -f *~ *.o *.d *.gcno *.gcda *.gcov libiw.a

intstall:
	@echo Nothing to be made

CFLAGS += -I ../..
CFLAGS += -I ../utils

include ../lib.rules


LIB_OBJS= peek_iface.o peek_netlink.o

libiw.a: $(LIB_OBJS)
	$(AR) crT $@ $?

-include $(OBJS:%.o=%.d)
