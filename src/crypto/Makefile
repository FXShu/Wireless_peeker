all: libcry.a

clean:
	rm -f *~ *.o *.d *.gcno *.gcda *.gcov libcrypto.a libcry.a

intstall:
	@echo Nothing to be made



include ../lib.rules

CONFIG_CRYPTO_INTERNAL=y


LIB_OBJS= sha1_internal.o crypto.o hmac_sha1.o sha1_pbkf2.o sha1-prf.o aes_openssl.o aes-ccm.o ccmp.o

libcry.a: $(LIB_OBJS)
	$(AR) crT $@ $?

-include $(OBJS:%.o=%.d)
