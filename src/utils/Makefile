all: libutils.a

clean:
	rm -f *~ *.o *.d *.gcno *.gcda *.gcov libutils.a

intstall:
	@echo Nothing to be made



include ../lib.rules

CONFIG_ELOOP_EPOLL=y


LIB_OBJS= \
	  eloop.o \
	  trace.o

libutils.a: $(LIB_OBJS)
	$(AR) crT $@ $?

-include $(OBJS:%.o=%.d)
