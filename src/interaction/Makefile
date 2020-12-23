all: libctrl.a

clean: 
	rm -f *~ *.o *.d *.gcno *.gcov libctrl.a
install:
	@echo Nothing to be made

include ../lib.rules

LIB_OBJS = peek_ctrl.o terminal.o peek_action.o

libctrl.a: $(LIB_OBJS)
	$(AR) crT $@ $?

-include $(OBJS:%.o=%.d)

