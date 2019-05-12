#include<stdio.h>

#include"packet.h"
#include<pcap/pcap.h>
#include<string.h>
#include"head.h"
#include"print.h"
void getGatewayMAC(u_char* user,const struct pcap_pkthdr* pkt,const u_char* data){
	ethernet_header* eth_header = (ethernet_header*)data;
	printf("gateway's MAC is ");
	print_mac(eth_header->SRC_mac);
}

int main(){
	char* dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program buf;
	char filter_app[100];
	dev = "wlp2s0";
	struct in_addr addr_net;
	u_int mask;
	u_int net_addr;
	char* net;
	char* real_mask;
	pcap_t *info;

	pcap_lookupnet(dev,&net_addr,&mask,errbuf);
	addr_net.s_addr = net_addr;
	net = inet_ntoa(addr_net);

	info = pcap_open_live(dev,1,65536,1000,errbuf);
	printf("pcap_open_live_successful\n");
	
	strcpy(filter_app,"icmp[icmptype] = icmp-echoreply");
	printf("filter_app copy successful\n");
	
	pcap_compile(info,&buf,filter_app,0,*net);
	printf("pcap_compile successful\n");
	
	pcap_setfilter(info,&buf);
	printf("pcap_setfilter successful\n");
	
	if(!ping("0.0.0.0")){
		printf("ping successful\n");
	}else{
		printf("ping fail\n");
		return -1;
	}
	
	pcap_loop(info,1,getGatewayMAC,NULL);
}
