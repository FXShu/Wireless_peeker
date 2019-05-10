#include"getif.h"

void getAttackerMAC(char* dev,u_char* mac){
	int sockfd;
	struct ifreq req;
	sockfd = socket(PF_INET,SOCK_DGRAM,0);
	strcpy(req.ifr_name,dev);
	ioctl(sockfd,SIOCGIFHWADDR,&req);
	strncpy(mac,req.ifr_hwaddr.sa_data,6);
}
int getifinfo(pcap_if_t** if_t,char* errbuf){
	if(!pcap_findalldevs(if_t,errbuf)){
		return 0;
	}else return -1;
}

bool checkdevice(pcap_if_t* if_buf,char* dev){
	bool get_dev =false;
	while(if_buf->next){
		if(!strcmp(dev,if_buf->name)){
			get_dev = true;
			break;
		}
		if_buf = if_buf->next;
	}
	return get_dev;
}
void getGatewayMAC(){

}
