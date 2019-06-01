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

//typedef unsigned char u_char;
void print_ip(unsigned char* ip);

void println_ip(unsigned char* ip);

void print_mac(unsigned char* mac);

void println_mac(unsigned char* mac);

void print_type(unsigned short type);

void print_protocol(unsigned char protocol_type);

void log_printf(int level,char* format,...);
#endif
