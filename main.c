#include "MITM.h"
#include "common.h"
#include "./src/interaction/mitm_ctrl.h"


char ip_s[MAX_IPV4_LEN];
char mac_s[MAX_MAC_LEN];
int debug_level;
bool manual=false;

void usage(){
	printf("MITM usage:\n"
		"MITM -i<interface name> -t<device_type> [-d<debug level>]...\n"
		"  -h = show this help\n"
		"  -d <level> = increase debugging verbosity\n"
		"  -i = interface name\n"
		"  -m = manual set interface information\n"
		"  -f <filter> set packet filter\n"
		"  -t <device_type(wireless/ethernet)> set the device type\n");
}

static void mitm_eloop_terminate(int sig, void *signal_ctx) {
	eloop_terminate();
}

int main(int argc,char* argv[]){

	struct MITM *MITM;

	bool filter_set = false;
	int c ,exitcode;
	char user_filter[100];
	struct packet_handler *handler;
	struct mitm_ctrl *ctrl;

	MITM = malloc(sizeof(struct MITM));
	if (!MITM)
		return -ENOMEM;

	for(;;){
		c=getopt(argc, argv,"i:hd:mf:w:t:p:");
		if(c < 0)break;
		switch(c){
		case 'd':
			debug_level = atoi(optarg);
		break;
		case 'h':
			usage();
			return 0;
		break;
		case 'i':
			MITM->usr_dev = optarg;
		break;
		case 'm':
			manual=true;	
		break;
		case 'f':
			strcpy(user_filter,optarg);
			filter_set = true;
		break;
		case 'w':
			MITM->pcapng_path = fopen(optarg, "w+");
		break;
		case 't':;
			char *tmp;
			tmp = strdup(optarg);
			if (!strcmp("wireless", tmp)) {
				MITM->dev_type = wireless;
			} else if (!strcmp("ethernet", tmp)) {
				MITM->dev_type = ethernet;
			} else {
				printf("only supper wireless/ethernet type device\n");
				usage();
				return -1;
			}
			free(tmp);
		break;
		case 'p':
			MITM->dict_path = strdup(optarg);
		break;
		default:
	       		usage();
			return 0;
		}
	}
#if 0
create_monitor_interface:
	if(MITM->dev_type == wireless) {
		printf( "type (yes/no) to create a monitor type interface or not\n"
			"also you can key the device name"
			", if you have already created a monitor mode interface:\n");

		char create_interface[10];
		if (scanf("%s", create_interface) == EOF) {
			log_printf(MSG_ERROR, "Invaild interface name.");
			return -1;
		}
		if (!strcmp(create_interface, "yes")) {
			MITM->monitor_dev = "mon0";
			log_printf(MSG_DEBUG, "creating a monitor interface base on %s", 
					MITM->usr_dev);
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
	}
#endif
	eloop_init();
	if (MITM_init(MITM) || !MITM) {
		log_printf(MSG_ERROR, "initialize global MITM failed");
		return -1;
	}
	if (!MITM->l2_packet) {
		log_printf(MSG_ERROR, "l2_packet_data alloc failed");
		goto fail;
	}
	ctrl = mitm_server_open(MITM, MITM_CTRL_PATH);
	if (!ctrl) {
		log_printf(MSG_ERROR, "control server open failed");
		goto fail;
	}else {
		log_printf(MSG_DEBUG, "control server is ready");
	}
	eloop_run();
fail:
	MITM_deinit(MITM);
	return -1;
}
