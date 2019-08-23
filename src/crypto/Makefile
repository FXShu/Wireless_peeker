all: libcrypto.a

clean:
	rm -f *~ *.o *.d *.gcno *.gcda *.gcov libcrypto.a

intstall:
	@echo Nothing to be made



include ../lib.rules

CONFIG_CRYPTO_INTERNAL=y


LIB_OBJS= sha1_internal.o

libcrypto.a: $(LIB_OBJS)
	$(AR) crT $@ $?

-include $(OBJS:%.o=%.d)
