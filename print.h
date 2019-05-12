#ifndef PRINTF_H
#define PRINTF_H
#include<stdio.h>
#include"head.h"

//typedef unsigned char u_char;
void print_ip(unsigned char* ip);

void print_mac(unsigned char* mac);

void print_type(unsigned short type);

void print_protocol(unsigned char protocol_type);
#endif
