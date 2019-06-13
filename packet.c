#include"packet.h"

extern bool debug;

unsigned short checksum(unsigned short* buf,int bufsz){
        unsigned int sum = 0xffff;
        while(bufsz>1){
                sum += *buf;
                buf++;
                bufsz -= 2;
        }
        if(bufsz == 1)sum += *(unsigned char*)buf;
        sum = (sum & 0xffff) + (sum >> 16);
        sum += (sum >>16 );

        return (unsigned short) ~sum;
}


int forword(char* dev,u_short pro_type, u_char* DST, u_char* SRC,
		const u_char* payload,int len){
	libnet_t* net_t;
	char errbuf[LIBNET_ERRBUF_SIZE];
	libnet_ptag_t tag; // typedef int32_t libnet_ptag_t
	net_t = libnet_init(LIBNET_LINK,dev,errbuf);
	if(!net_t){
		log_printf(MSG_DEBUG,"error: %s\n",errbuf);
		return -1;
	}	
	tag = libnet_build_ethernet(DST,SRC,pro_type,payload,len,net_t,0);
	if(tag<0){
		log_printf(MSG_DEBUG,"error : %s\n",libnet_geterror(net_t));
		libnet_destroy(net_t);
		return -1;
	}
	if(libnet_write(net_t) < 0){
		log_printf(MSG_DEBUG,"error : %s\n",libnet_geterror(net_t));
		libnet_destroy(net_t);
		return -1;
	}
	libnet_destroy(net_t);
	return 0;
}

int ping(unsigned char* dest_ip){
	int sockfd;
	struct icmphdr hdr;
	struct sockaddr_in addr;
	sockfd = socket(AF_INET,SOCK_RAW,IPPROTO_ICMP);
	if(sockfd<0) return -1;
	
	memset(&hdr,0,sizeof(hdr));

	addr.sin_family=AF_INET;
	memset(&addr.sin_zero,0,sizeof(addr.sin_zero));
	inet_pton(AF_INET,dest_ip,&addr.sin_addr);

	hdr.type = ICMP_ECHO;
	hdr.code = 0;
	hdr.checksum = 0;
	hdr.un.echo.id = 0;
	hdr.un.echo.sequence = 0;
	hdr.checksum = checksum((unsigned short*)&hdr,sizeof(hdr));
	
	if(sendto(sockfd,&hdr,sizeof(hdr),0,(struct sockaddr*)&addr,sizeof(addr))==-1){
		return -1;
	}
	close(sockfd);
	return 0;
}
