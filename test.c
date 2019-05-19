#include<stdio.h>

#include"packet.h"
#include<pcap/pcap.h>
#include<string.h>
#include"head.h"
#include"sniffer.h"
#include"print.h"
void getgatewayMAC(u_char* user,const struct pcap_pkthdr* pkt,const u_char* data){
	sni_info* sni = (sni_info*)user;
	ethernet_header* eth_header = (ethernet_header*)data;
	printf("gateway's MAC is ");
	print_mac(eth_header->SRC_mac);
	strcpy(sni->gateway_mac, eth_header->SRC_mac);
	print_mac(sni->gateway_mac);
	
}

int main(){
	bool debug;
	char* dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program buf;
	char filter_app[100];
	dev = "wlp3s0";
	struct in_addr addr_net;
	u_int mask;
	u_int net_addr;
	char* net;
	char* real_mask;
	pcap_t *info;
	sni_info sni_info;
	pcap_lookupnet(dev,&net_addr,&mask,errbuf);
	addr_net.s_addr = net_addr;
	net = inet_ntoa(addr_net);

	info = pcap_open_live(dev,0,65536,1000,errbuf);
	//interface type need to be unpromisc,if set interface to promisc, 
	//the SRC_mac in etherheader of packet capute will be loss 
	printf("pcap_open_live_successful\n");
	
	strcpy(filter_app,"icmp[icmptype] = icmp-echoreply");	
//	strcpy(filter_app,"icmp");
	printf("filter_app copy successful\n");

	
	if(!pcap_compile(info,&buf,filter_app,0,*net)){
		printf("pcap_compile successful\n");
	}else{
		printf("pcap_compile fail\n");
	}

	if(!pcap_setfilter(info,&buf)){
		printf("pcap_setfilter successful\n");
	}else{
		printf("pcap_setfilter fail\n");
	}
	if(!ping("8.8.8.8")){
		printf("ping successful\n");
	}else{
		printf("ping fail\n");
		return -1;
	}
	
	pcap_loop(info,1,getgatewayMAC,(u_char*)&sni_info);

	print_mac(sni_info.gateway_mac);
        info = pcap_open_live(dev,0,65536,1000,errbuf);
	if(info){
		printf("successful\n");
	}else{
		printf("fail\n");
	}
}
