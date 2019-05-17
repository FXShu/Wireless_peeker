#include"getif.h"

void getAttackerInfo(char* dev,u_char* mac,u_char* ip){
	int sockfd;
	struct ifreq req;
	sockfd = socket(PF_INET,SOCK_STREAM,0);
	strcpy(req.ifr_name,dev);
        ioctl(sockfd,SIOCGIFADDR,&req);
	/*for (int i=0;i<14;i++){
		printf("%d ",req.ifr_addr.sa_data[i]);
	}*/
        strncpy(ip,req.ifr_addr.sa_data+2,4);
	ioctl(sockfd,SIOCGIFHWADDR,&req);
	strncpy(mac,req.ifr_hwaddr.sa_data,6);
	close(sockfd);
}

int getifinfo(pcap_if_t** if_t,char* errbuf){
	if(!pcap_findalldevs(if_t,errbuf)){
		return 0;
	}
	return -1;
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

