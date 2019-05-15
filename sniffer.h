#ifndef SNIFFER_H
#define SNIFFER_H

#include<pcap/pcap.h>
#include<netinet/in.h>
#include<stdio.h>
#include<arpa/inet.h>
#include<string.h>
#include<stdlib.h>

#include"getif.h"
#include"head.h"
#include"common.h"
#include"print.h"
#include"packet.h"

typedef enum {
	FromVictim,
	FromGateway
}dirtection;

typedef struct {
	char* dev;
	pcap_t* handle;
	char* mask;
	char* net;
	struct bpf_program filter;
	char filter_app[100];
	unsigned char gateway_mac[6];
	unsigned char attacker_ip[4];
	unsigned char attacker_mac[6];
}sni_info;

int sniffer_init(sni_info* info,char* errbuf);

void Sniffer(const char* filter_exp);

int getPacket(u_char* arg,const struct pcap_pkthdr* hp,const u_char* packet,char* data);
#endif
