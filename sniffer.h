#ifndef SNIFFER_H
#define SNIFFER_H
/*
#include<unistd.h>
#include<linux/netlink.h>
#include<linux/rtnetlink.h>
#include<pcap/pcap.h>
#include<netinet/in.h>
#include<stdio.h>
#include<arpa/inet.h>
#include<string.h>
#include<stdlib.h>
#include<signal.h>
*/
#include "include.h"
#include"getif.h"
#include"packet.h"
#include"parse.h"
#include"common.h"
//#include"./src/utils/head.h"

typedef enum {
	FromVictim,
	FromGateway
}dirtection;

typedef struct {
	char* dev;
	uint8_t ap_BSSID[ETH_ALEN]; /* only use when device type is wireless */
	pcap_t* handle;
	char* mask;
	char* net;
	struct bpf_program filter;
	char filter_app[100];
	unsigned char gateway_ip[4];
	unsigned char gateway_mac[6];
	unsigned char attacker_ip[4];
	unsigned char attacker_mac[6];
	unsigned char target_ip[4];
	unsigned char target_mac[6];
}sni_info;


struct packet_handler{
	int fd;
	pcap_t* pcap_fd;
};

int sniffer_init(sni_info* info,char* errbuf);

void Sniffer(const char* filter_exp);

int getPacket(u_char* arg,const struct pcap_pkthdr* hp,const u_char* packet,char* data);

struct packet_handler* pcap_fd_init(void* mitm_info);

void anlysis_packet(int sock, void *eloop_ctx, void *sock_ctx);
#endif
