#ifndef PACKET_H
#define PACKET_H

#ifndef LIBNET_H
#define LIBNET_H
#include<libnet.h>
#endif
#endif

typedef unsigned short u_short;
typedef unsigned char  u_char;

int forword(char* dev, u_short pro_type,u_char* DST,u_char* SRC,
		const u_char* payload,int len,int Times);
