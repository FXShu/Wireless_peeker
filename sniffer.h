#ifndef SNIFFER_H
#define SNIFFER_H
#include<pcap.h>
#include<stdio.h>
#include<stdlib.h>
#include<arpa/inet.h>
#include<string.h>

#include"head.h"

typedef enum {
	FromVictim,
	FromGateway
}dirtection;

void Sniffer(const char* filter_exp);

void print_ip(u_char* ip);

void print_mac(u_char* mac);

void print_type(u_short type);

void print_protocol(u_char protocol_type);

int getPacket(u_char* arg,const struct pcap_pkthdr* hp,const u_char* packet,char* data);
#endif
