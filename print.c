#include"print.h"

void print_ip(unsigned char* ip){
	for(int i=0;i<4;i++){
		printf("%d",ip[i]);
		if(i<3)printf(".");
	}
}

void println_ip(unsigned char* ip){
        for(int i=0;i<4;i++){
                printf("%d",ip[i]);
                if(i<3)printf(".");
        }
        printf("\n");
}

void print_mac(unsigned char* mac){
	for(int i=0;i<6;i++){
		if(mac[i]<16)printf("0");
		printf("%x",mac[i]);
		if(i<5)printf(":");
	}
}

void println_mac(unsigned char* mac){
        for(int i=0;i<6;i++){
                if(mac[i]<16)printf("0");
                printf("%x",mac[i]);
                if(i<5)printf(":");
        }
        printf("\n");
}

void print_type(unsigned short type){
	switch(type){
		case EPT_IPv4 : printf("eth type : IPv4\n");break;
		case EPT_IPv6 : printf("eth type : IPv6\n");break;
		case EPT_ARP  : printf("eth type : ARP\n");break;
		case EPT_RARP : printf("eth type : RARP\n");break;
		default : printf("eth type : Unknow type\n");
	}
}

void print_protocol(unsigned char protocol_type){
	switch(protocol_type){
		case PROTOCOL_TCP : printf("protocol type : TCP\n");break;
		case PROTOCOL_UDP : printf("protocol type : UDP\n");break;
		case PROTOCOL_ICMP :printf("protocol type : ICMP\n");break;
		default : printf("Unknown type\n");
	}
}
