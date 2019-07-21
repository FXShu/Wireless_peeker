#include"print.h"
extern int debug_level;
void print_ip(unsigned char* ip){
	for(int i=0;i<4;i++){
		printf("%d",ip[i]);
		if(i<3)printf(".");
	}
}

char* ip4tostring(char* ip_s,unsigned char* ip){
        sprintf(ip_s,"%d.%d.%d.%d",ip[0],ip[1],ip[2],ip[3]);
        return ip_s;
}

char* mactostring(char* mac_s,unsigned char* mac){
	sprintf(mac_s,"%x:%x:%x:%x:%x:%x",mac[0],mac[1],mac[2],
					mac[3],mac[4],mac[5]);
	return mac_s;
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

void log_printf(int level,char* format,...){
	va_list ap;
	va_start(ap,format);
	if(level >= debug_level){
		vprintf(format,ap);
		printf("\n");
	}
	va_end(ap);
}
