#ifndef SNIFFER_H
#define SNIFFER_H
#include<pcap/pcap.h>
#include<netinet/in.h>
#include<stdio.h>
#include<stdlib.h>
#include<arpa/inet.h>
#include<string.h>

#include"head.h"
#include"common.h"
typedef enum {
	FromVictim,
	FromGateway
}dirtection;

typedef struct{
	char* dev;
	pcap_t* handle;
	char* mask;
	char* net;
	struct bpf_program filter;
	char filter_app[100];
}sni_info;

int sniffer_init(sni_info* info,char* errbuf);

void Sniffer(const char* filter_exp);

void print_ip(u_char* ip);

void print_mac(u_char* mac);

void print_type(u_short type);

void print_protocol(u_char protocol_type);

int getPacket(u_char* arg,const struct pcap_pkthdr* hp,const u_char* packet,char* data);
#endif
