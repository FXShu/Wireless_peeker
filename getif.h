#ifndef GETIF_H
#define GETIF_H
#include"common.h"

#ifndef PCAP_PCAP_H
#define PCAP_PCAP_H
#include<pcap/pcap.h>
#endif /* PCAP_PCAP_H */

#include<sys/socket.h>
#include<sys/ioctl.h>
#include<net/if.h>

#ifndef STRING_H
#define STRING_H
#include<string.h>
#endif /* STRING_H */

typedef unsigned char u_char;

void getAttackerMAC(char* dev,u_char* mac);
void getGatewayMAC();
int  getifinfo(pcap_if_t** if_t,char* errbuf);
bool checkdevice(pcap_if_t* if_buf,char* dev);
#endif /* GETIF_H */
