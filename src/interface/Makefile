all: libiw.a

clean:
	rm -f *~ *.o *.d *.gcno *.gcda *.gcov libiw.a

intstall:
	@echo Nothing to be made



include ../lib.rules


LIB_OBJS= \
	  interface_handle.o iw_implement.o \

libiw.a: $(LIB_OBJS)
	$(AR) crT $@ $?

-include $(OBJS:%.o=%.d)
