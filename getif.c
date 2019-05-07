#include"getif.h"


void getAttackerMAC(char* dev,u_char* mac){
	int sockfd;
	struct ifreq req;
	sockfd = socket(PF_INET,SOCK_DGRAM,0);
	strcpy(req.ifr_name,dev);
	ioctl(sockfd,SIOCGIFHWADDR,&req);
	strncpy(mac,req.ifr_hwaddr.sa_data,6);
}

void getGatewayMAC(){

}
