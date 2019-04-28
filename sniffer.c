#include <pcap/pcap.h>
#include<netinet/in.h>
#include"sniffer.h"

void print_ip(u_char* ip){
	for(int i=0;i<4;i++){
		printf("%d",ip[i]);
		if(i<3)printf(".");
	}
	printf("\n");
}

void print_mac(u_char* mac){
	for(int i=0;i<6;i++){
		if(mac[i]<16)printf("0");
		printf("%x",mac[i]);
		if(i<5)printf(":");
	}
	printf("\n");
}

void print_type(u_short type){
	switch(type){
		case EPT_IPv4 : printf("eth type: IPv4\n");break;
		case EPT_IPv6 : printf("eth type: IPv6\n");break;
		case EPT_ARP  : printf("eth type: ARP\n");break;
		case EPT_RARP : printf("eth type: RARP\n");break;
		default : printf("eth type : Unknown type\n");
	}
}

void print_protocol(u_char protocol_type){
	switch(protocol_type){
		case PROTOCOL_TCP : printf("protocol type: TCP\n");break;
		case PROTOCOL_UDP : printf("protocol type: UDP\n");break;
		default : printf("Unknown type\n");
	}
}

void proc_pkt(u_char* user,const struct pcap_pkthdr* hp,const u_char* packet){
	ethernet_header* pEther;
	ip_header* pIpv4;
	arp_header* pArp;
	pEther = (ethernet_header*)packet;
	printf("--------------------------------------\n");
	print_type(ntohs(pEther->eth_type));
	printf("eth src MAC address is :");
	print_mac(pEther->SRC_mac);
	printf("eth des MAC address is :");
	print_mac(pEther->DST_mac);

	/* settle ip */
	if(ntohs(pEther->eth_type) == EPT_IPv4){
		pIpv4 = (ip_header*)(packet + sizeof(ethernet_header));
		print_protocol(pIpv4->protocol_type);
	        printf("src IP address is:");
		print_ip(pIpv4->src_ip);
		printf("des IP address is :");
                print_ip(pIpv4->dest_ip);
	
	        /* settle port*/
	        if(pIpv4->protocol_type == PROTOCOL_TCP){
		        tcp_header* pTcp;
		        pTcp = (tcp_header*)(packet + sizeof(ethernet_header) + sizeof(ip_header));
		        printf("src port address is: %hu\n", ntohs(pTcp->sour_port));
		        printf("des port address is :%hu\n", ntohs(pTcp->dest_port));
	        }
	        else if (pIpv4->protocol_type == PROTOCOL_UDP){
		        udp_header* pUdp;
		        pUdp = (udp_header*)(packet + sizeof(ethernet_header) + sizeof(ip_header));
	 	        printf("src port address is : %hu\n",ntohs(pUdp->sour_port));
		        printf("des port address is : %hu\n",ntohs(pUdp->dest_port));
	        }
	}else if (ntohs(pEther->eth_type) == EPT_ARP){
		pArp = (arp_header*)(packet + sizeof(ethernet_header));
		printf("src MAC address is:");
		print_mac(pArp->src_mac);
		printf("eth des address is:");
		print_mac(pArp->dest_mac);
		printf("src IP address is :");
		print_ip(pArp->src_ip);
		printf("des IP address is :");
		print_ip(pArp->dest_ip);
	}

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
void Sniffer (const char* filter_exp){
        char* dev;
        char errbuf[PCAP_ERRBUF_SIZE];
        u_int mask;
        u_int net_addr;
        char* net;
        char* real_mask;
        struct in_addr addr_net;
        pcap_t* handle;
        struct bpf_program filter;
        char filter_app[100];

        /* start dev */
        dev = pcap_lookupdev(errbuf);
        if(dev == NULL){
                printf("%s\n",errbuf);
                exit(1);
        }
        /* start device */
        if (pcap_lookupnet(dev, &net_addr,&mask,errbuf) == -1 ){
                printf("%s\n",errbuf);
                exit(1);
        }

        addr_net.s_addr = mask;
        real_mask = inet_ntoa(addr_net);
        printf("\nmask: %s\n",real_mask);
        addr_net.s_addr = net_addr;
        net = inet_ntoa(addr_net);

        handle = pcap_open_live(dev,65536,1,1000,errbuf);

        if(!handle){
                printf("%s\n",errbuf);
                printf("If the problem is \"you don't have permission\",please run this program as root!\n");
                exit(1);
        }

        /*filtering*/
        if (filter_exp != NULL) strcpy(filter_app,filter_exp);
        pcap_compile(handle,&filter,filter_app,0,*net);
        pcap_setfilter(handle,&filter);

        /*loop caputring*/
        printf("\nstart sniff:\n\n");
        pcap_loop(handle,-1 ,proc_pkt,NULL);

        /* end */
        pcap_close(handle);
}

void getgatewayMAC(u_char* user,const struct pcap_pkthdr* hp, const u_char* packet){
}
