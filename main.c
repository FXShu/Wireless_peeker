#include<unistd.h>
#include<pthread.h>
#include"common.h"
#include"arp.h"
#include"sniffer.h"
#include"getif.h"
#include"print.h"
char ip_s[MAX_IPV4_LEN];
char mac_s[MAX_MAC_LEN];
int debug_level;
char *wfile;
bool manual=false;
void usage(){
	printf("MITM usage:\n"
		"  -h = show this help test\n"
		"  -d <level> = increase debugging verbosity\n"
		"  -i = interface name\n"
		"  -l = list all available interface\n"
		"  -m = manual set interface information\n"
		"  -f <filter> set packet filter\n");
}

int main(int argc,char* argv[]){
	bool filter_set = false;
	int c ,exitcode;
	char user_filter[100];
	sni_info dev_info;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t* if_buf;
	char* usr_dev;
	for(;;){
		c=getopt(argc, argv,"i:hd:lmf:w:");
		if(c < 0)break;
		switch(c){
			case 'h':
				usage();
				goto out;
			break;
			case 'd':
				debug_level = atoi(optarg);
			break;
			case 'i':
				usr_dev = optarg;
			break;
			case 'l':
				if(getifinfo(&if_buf,errbuf)){
                                        exitcode = 10;
					goto out;
				}
				
				while(if_buf->next){
                                                printf("%s\n",if_buf->name);
                                                if_buf = if_buf->next;
				}
				return 0;
			break;
			case 'm':
				manual=true;	
			break;
			case 'f':
				strcpy(user_filter,optarg);
				filter_set = true;
			break;
			case 'w':
				wfile=optarg;
			break;
			default:
		       		usage();
				goto out;	
		}
	}
	
	if(getifinfo(&if_buf,errbuf)){
		exitcode = 10;
		goto out;
	}
	if(!checkdevice(if_buf,usr_dev)){
		exitcode = 11;
		goto out;
	}
	if(filter_set) {
		strcat(user_filter," && not arp");
	} else {
		strcpy(user_filter,"not arp");
	}
	printf("please type target's ip = ");
	scanf("%hhd.%hhd.%hhd.%hhd",&dev_info.target_ip[0],&dev_info.target_ip[1],
			&dev_info.target_ip[2],&dev_info.target_ip[3]);

	/* sniffer init */
	dev_info.dev=usr_dev;
	if(exitcode = sniffer_init(&dev_info,errbuf)){
		goto out;
	}
	printf("sniffer init successful\n");
	//strcat(user_filter," && ether src 40:9f:38:82:fc:2b");	
	if(manual){
		printf("type gateway's mac\n");
		scanf("%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",&dev_info.gateway_mac[0],&dev_info.gateway_mac[1],
					&dev_info.gateway_mac[2],&dev_info.gateway_mac[3],
					&dev_info.gateway_mac[4],&dev_info.gateway_mac[5]);
		printf("type gateway's ip\n");
		scanf("%hhd.%hhd.%hhd.%hhd",&dev_info.gateway_ip[0],&dev_info.gateway_ip[1],
					&dev_info.gateway_ip[2],&dev_info.gateway_ip[3]);
		printf("type target's mac\n");
		scanf("%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",&dev_info.target_mac[0],&dev_info.target_mac[1],
                                        &dev_info.target_mac[2],&dev_info.target_mac[3],
                                        &dev_info.target_mac[4],&dev_info.target_mac[5]);
		printf("type gateway's ip\n");
		scanf("%hhd.%hhd.%hhd.%hhd",&dev_info.target_ip[0],&dev_info.target_ip[1],
                                        &dev_info.target_ip[2],&dev_info.target_ip[3]);
	}

        MITM_info info={
                .TARGET_MAC=dev_info.target_mac,
                .ATTACKER_MAC=dev_info.attacker_mac,
                .GATEWAY_MAC=dev_info.gateway_mac,
                .TARGET_IP=dev_info.target_ip,
                .GATEWAY_IP=dev_info.gateway_ip,
	};
        strcpy(info.dev,usr_dev);
	info.filter = user_filter;
	/* init fake arp and the return value should be the next input to send_fake_arp op */

	pthread_t arp_td;
	pthread_t cap_td;
	//the thread of arp_spoof need to be detached or joinable?
	pthread_attr_t a;
	pthread_attr_init(&a);
	pthread_attr_setdetachstate(&a,PTHREAD_CREATE_DETACHED);


	pthread_create(&arp_td,NULL,arp_spoof,&info);
	pthread_create(&cap_td,NULL,capute,&info);
	//pthread_join(arp_td,NULL);
	pthread_join(cap_td,NULL);

	free(if_buf);	
	return 0;

out :
	switch(exitcode){
		case 10:
			printf("can't find device info,please run by superuser again\n");
		break;
		case 11:
			printf("can't find specify interface,please check by flag 'l'\n");
		break;
		case 12:
			printf("gateway is not exist or reject ping packet\n");
		break;
		case 13:
			printf("target is not exist or reject ping packet\n");
		break;
	}
	return -1;
}
