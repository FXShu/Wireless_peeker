#CROSS=arm-openwrt-linux-
CROSS=
CC=$(CROSS)gcc 
CFLAGS = -g -O0 -std=gnu99  -Wno-switch -Wno-unused-variable -MMD
CFLAGS += -I$(abspath ./src)
CFLAGS += -I$(abspath ./src/utils)
CFLAGS += -I$(abspath ./src/crypto)
CFLAGS += -I /usr/include/libnl3

CFLAGS_CLI = -g -std=c99

LIBS_c=
LIBS_CLI_c=
LIBS_SEND=

OBJS= 
OBJS_CLI =

OBJS += main.o parse.o wireless_peek.o
OBJS_CLI += wireless_peek_cli.o

OBJS_SEND += send_packet_test.o 

LIBS_c += -lnet
LIBS_c += -lm
LIBS_c += -L ./src/interaction -lctrl
LIBS_c += -L ./src/l2_packet -ll2_packet
LIBS_c += -L ./src/crypto -lcry
LIBS_c += -L ./src/interface -liw
LIBS_c += -lnl-3 -lnl-genl-3
LIBS_c += -L ./src/utils -lutils
LIBS_c += -lssl -lcrypto
LIBS_c += -L ./src/pcapng -lpcapng

LIBS_CLI_c += -L ./src/interaction -lctrl
LIBS_CLI_c += -L ./src/l2_packet -ll2_packet
LIBS_CLI_c += -L ./src/crypto -lcry
LIBS_CLI_c += -L ./src/utils -lutils
LIBS_CLI_c += -lm
LIBS_CLI_c += -lssl -lcrypto
LIBS_CLI_c += -L ./src/pcapng -lpcapng

BINALL=wireless_peeker peeker_cli
.phony : ALL
ALL = $(BINALL)
all: install $(ALL)

export CFLAGS CC
#ifdef CONFIG_ELOOP_EPOLL
CFLAGS += -DCONFIG_ELOOP_EPOLL -DCONFIG_CRYPTO_INTERNAL -DCONFIG_CTRL_IFACE_UNIX
#endif

wireless_peeker : $(OBJS)	
	$(CC) $(CFLAGS) $(OBJS) -o $@ $(LIBS_c)
.phony : MITM_cli
peeker_cli : $(OBJS_CLI)
	$(CC) $(CFLAGS) $(OBJS_CLI) -o $@ $(LIBS_CLI_c)

install: 
	$(MAKE) -C src

Q=@
E=echo
ifeq ($(V),1)
Q=
E=true
endif
ifeq ($(QUIET), 1)
Q=@
E=true
endif

ifdef CONFIG_CODE_CEVERAGE
%.o: %.c
	@$(E) "	CC " $<
	$(Q)cd $(dir $@); $(CC) -c -o $(notdir $@) $(CFLAGS) $(notdir $<)
else
%.o: %.c
	$(Q)$(CC) -c -o $@ $(CFLAGS) $<
	@$(E) "	CC " $<
endif

clean:
	$(MAKE) -C src clean
	rm *.o *.d
	rm $(ALL)

