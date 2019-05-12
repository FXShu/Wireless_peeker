#ifndef ARP_H
#define ARP_H

#ifndef LIBNET_H
#define LIBNET_H
#include<libnet.h>
#endif /* LIBNET_H */

#include"head.h"
#include"common.h"
#include"print.h"
int send_fake_ARP(char* dev, u_char* srcMac, u_char* destMac, u_char* srcIp, u_char* destIp,int op);
void* arp_spoof(void* info);
#endif
