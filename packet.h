#ifndef PACKET_H
#define PACKET_H

#include<libnet.h>
#include<string.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<netinet/ip.h>
#include<netinet/ip_icmp.h>
#include<arpa/inet.h>

#include"common.h"
#include"head.h"
#include"print.h"
typedef unsigned short u_short;
typedef unsigned char  u_char;

int forword(char* dev, u_short pro_type,u_char* DST,u_char* SRC,
		const u_char* payload,int len);

int ping(unsigned char* dest_ip);

#endif
