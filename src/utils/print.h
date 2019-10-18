#ifndef PRINTF_H
#define PRINTF_H
#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include "head.h"

enum {
	MSG_EXCESSIVE,
	MSG_MSGDUMP,
	MSG_DEBUG,
	MSG_INFO,
	MSG_WARNING,
	MSG_ERROR
};

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif /* ETH_ALEN */

#define MAC2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]
#define MACSTR "%02x:%02x:%02x:%02x:%02x:%02x"

#define IPv42STR(a) (a)[0], (a)[1], (a)[2], (a)[3]
#define IPv4STR "%d.%d.%d.%d"

#define PRINTF_MALLOC_ERROR log_printf(MSG_ERROR, "%s,%d: malloc failed by %s", \
					__func__, __LINE__, strerror(errno)); return NULL

//typedef unsigned char u_char;
char* ip4tostring(char*,unsigned char*);

char* mactostring(char*,unsigned char*);

void print_ip(unsigned char* ip);

void println_ip(unsigned char* ip);

void print_mac(unsigned char* mac);

void println_mac(unsigned char* mac);

void print_type(unsigned short type);

void print_protocol(unsigned char protocol_type);

void log_printf(int level,char* format,...);

void copy_mac_address(uint8_t *src, uint8_t *dst);
#endif
