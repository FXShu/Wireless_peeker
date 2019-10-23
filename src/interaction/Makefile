all: libctrl.a

clean: 
	rm -f *~ *.o *.d *.gcno *.gcov libctrl.a
install:
	@echo Nothing to be made

include ../lib.rules

LIB_OBJS = mitm_ctrl.o terminal.o mitm_action.o

libctrl.a: $(LIB_OBJS)
	$(AR) crT $@ $?

-include $(OBJS:%.o=%.d)

