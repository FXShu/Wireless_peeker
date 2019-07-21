#ifndef PRINTF_H
#define PRINTF_H
#include<stdio.h>
#include<stdarg.h>
#include"head.h"

enum {
	MSG_EXCESSIVE,
	MSG_MSGDUMP,
	MSG_DEBUG,
	MSG_INFO,
	MSG_WARNING,
	MSG_ERROR
};

#define MAC2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]
#define MACSTR "%02x:%02x:%02x:%02x:%02x:%02x"

#define IPv42STR(a) (a)[0], (a)[1], (a)[2], (a)[3]
#define IPv4STR "%d.%d.%d.%d"

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
#endif
