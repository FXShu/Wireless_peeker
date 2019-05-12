#include"packet.h"

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
		const u_char* payload,int len,int Times){
	
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
		printf()
		return -1;
	}
	return 0;
}
