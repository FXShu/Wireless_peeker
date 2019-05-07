#include<sys/socket.h>
#include<sys/ioctl.h>
#include<net/if.h>

#ifndef STRING_H
#define STRING_H
#include<string.h>
#endif

typedef unsigned char u_char;

void getAttackerMAC(char* dev,u_char* mac);
void getGatewayMAC();
