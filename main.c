#include<unistd.h>
#include "common.h"
#include "MITM.h"

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

void print_ap_list(void *eloop_data, void *user_ctx) {
	struct MITM* MITM = (struct MITM*) user_ctx;
	if (!MITM) return;
	
	print_hashtable(&MITM->ap_list);
}

static void mitm_eloop_terminate(int sig, void *signal_ctx) {
	eloop_terminate();
}

int main(int argc,char* argv[]){

	struct MITM *MITM;

	bool filter_set = false;
	int c ,exitcode;
	char user_filter[100];
	//sni_info dev_info;
	//char errbuf[PCAP_ERRBUF_SIZE];
	//pcap_if_t* if_buf;
	//pcap_if_t* monitor_buf;
	//char* usr_dev;
	//char* monitor_dev = "mon0";
	struct packet_handler *handler;
	//struct l2_packet_data *l2_shakehand;
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
				MITM->usr_dev = optarg;
			break;
			case 'l':
				if(getifinfo(&MITM->if_buf,MITM->errbuf)){
                                        exitcode = 10;
					goto out;
				}
				
				while(MITM->if_buf->next){
                                                printf("%s\n",MITM->if_buf->name);
                                                MITM->if_buf = MITM->if_buf->next;
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
create_monitor_interface:
	printf( "If you are using wireless interface to capute traffic\n"
		"that must to create a monitor mode interface\n"
		"you can type (yes/no) to create interface or not\n"
		"also you can key the device name"
		", if you have already created a monitor mode interface:\n");

	char create_interface[10];
	scanf("%s", create_interface);
	if (!strcmp(create_interface, "yes")) {
		log_printf(MSG_DEBUG, "creating a monitor interface base on %s", MITM->usr_dev);
		char* interface_add_command[6] = {"dev", "interface", "add",
		       	MITM->monitor_dev,"type", "monitor"};
		if(!nl80211_init()) {
			if(!interface_handler(interface_add_command)) {
				if(if_up(MITM->monitor_dev) < 0) 
					return -1;
				log_printf(MSG_DEBUG, 
						"hang up monitor interface %s successful", 
						MITM->monitor_dev);
			}
		} 
	} else if (!strcmp(create_interface, "no")) {
		log_printf(MSG_DEBUG, "seem you are a rebellious guy em....");
		return -1;
	} else {
		if(!getifinfo(&MITM->monitor_buf, MITM->errbuf)) {
			if(!checkdevice(MITM->monitor_buf, create_interface)) {
				log_printf(MSG_INFO, "can't find the device %s,"
					       	"please check again!\n",create_interface);
				goto create_monitor_interface;
			} else {
				//strcpy(monitor_dev, create_interface);
				MITM->monitor_dev = create_interface;
			}
		}
	}

	eloop_init();

	MITM_init(MITM);

	if (!MITM->l2_packet) {
		log_printf(MSG_ERROR, "l2_packet_data alloc failed");
		goto out;
	}
	eloop_run();

	if(filter_set) {
		strcat(user_filter," && not arp");
	} else {
		strcpy(user_filter,"not arp");
	}
/*
	printf("please type target's ip = ");
	scanf("%hhd.%hhd.%hhd.%hhd",&dev_info.target_ip[0],&dev_info.target_ip[1], 
			&dev_info.target_ip[2],&dev_info.target_ip[3]);

	dev_info.dev=usr_dev;
	if(exitcode = sniffer_init(&dev_info,errbuf)){
		goto out;
	}
	log_printf(MSG_DEBUG, "sniffer init successful");
*/

	if(manual){
		log_printf(MSG_INFO, "type gateway's mac");
		scanf("%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &MITM->dev_info.gateway_mac[0],
				&MITM->dev_info.gateway_mac[1], &MITM->dev_info.gateway_mac[2],
				&MITM->dev_info.gateway_mac[3], &MITM->dev_info.gateway_mac[4],
				&MITM->dev_info.gateway_mac[5]);
		log_printf(MSG_INFO, "type gateway's ip");
		scanf("%hhd.%hhd.%hhd.%hhd", &MITM->dev_info.gateway_ip[0], 
				&MITM->dev_info.gateway_ip[1], &MITM->dev_info.gateway_ip[2],
			       	&MITM->dev_info.gateway_ip[3]);
		log_printf(MSG_INFO, "type target's mac");
		scanf("%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &MITM->dev_info.target_mac[0],
				&MITM->dev_info.target_mac[1], &MITM->dev_info.target_mac[2],
				&MITM->dev_info.target_mac[3], &MITM->dev_info.target_mac[4],
				&MITM->dev_info.target_mac[5]);
		log_printf(MSG_INFO, "type gateway's ip");
		scanf("%hhd.%hhd.%hhd.%hhd",&MITM->dev_info.target_ip[0], 
				&MITM->dev_info.target_ip[1], &MITM->dev_info.target_ip[2],
				&MITM->dev_info.target_ip[3]);
	}

        MITM_info info={
                .TARGET_MAC=MITM->dev_info.target_mac,
                .ATTACKER_MAC=MITM->dev_info.attacker_mac,
                .GATEWAY_MAC=MITM->dev_info.gateway_mac,
                .TARGET_IP=MITM->dev_info.target_ip,
                .GATEWAY_IP=MITM->dev_info.gateway_ip,
	};
	
        strcpy(info.dev,MITM->usr_dev);
	info.filter = user_filter;
	/* init fake arp and the return value should be the next input to send_fake_arp op */
	//use eloop meshanism to replace create new thread
	eloop_register_timeout(1, 0, arp_spoof, NULL, &info);
	handler = pcap_fd_init(&info);
	if(!handler) {
		log_printf(MSG_ERROR, "init pcap handler failed");
		goto out;
	} else {
		eloop_register_read_sock(handler->fd, anlysis_packet, &info, handler);
	}
	eloop_register_signal_terminate(mitm_eloop_terminate, NULL);
	eloop_run();
	//free(if_buf);	
	//free(handler);
	//l2_packet_deinit(l2_shakehand);
	MITM_deinit(MITM);
	return 0;

out :
	switch(exitcode){
		case -1:
			log_printf(MSG_ERROR, "unkonwn failure");
		break;
		case 10:
			log_printf(MSG_ERROR, "can't find device info,please run by superuser again");
		break;
		case 11:
			log_printf(MSG_ERROR, "can't find specify interface,please check by flag 'l'");
		break;
		case 12:
			log_printf(MSG_ERROR, "gateway is not exist or reject ping packet");
		break;
		case 13:
			log_printf(MSG_ERROR, "target is not exist or reject ping packet");
		break;
	}
//	free(if_buf);
//	free(handler);
//	l2_packet_deinit(l2_shakehand);
	MITM_deinit(MITM);
	return -1;
}
