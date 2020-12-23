#include "wireless_peek.h"
#include "common.h"
#include "./src/interaction/peek_ctrl.h"

int debug_level;

void usage(){
	printf("MITM usage:\n"
		"MITM -i<interface name> -t<device_type> [-d<debug level>]...\n"
		"  -h = show this help\n"
		"  -d <level> = increase debugging verbosity\n"
		"  -i = interface name\n"
		"  -t <device_type(wireless/ethernet)> set the device type\n");
}

static void mitm_eloop_terminate(int sig, void *signal_ctx) {
	eloop_terminate();
}

int main(int argc, char **argv){

	struct wireless_peek this;

	char packet_path[64];
	char main_iface[64];
	char dictionary_path[64];
	int c;
	struct mitm_ctrl *ctrl;

	for(;;){
		c=getopt(argc, argv,"i:hd:w:p:");
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
			strncpy(main_iface, optarg, 64);
		break;
		case 'w':
			strncpy(packet_path, optarg, 64);
		break;
		case 'p':
			strncpy(dictionary_path, optarg, 64);
		break;
		default:
	       		usage();
			return 0;
		}
	}
	eloop_init();

	memset(&this, 0, sizeof(struct wireless_peek));
	if (wireless_peek_init(&this, main_iface, dictionary_path, packet_path))
		goto exit;
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
	eloop_run();
exit:
	wireless_peek_deinit(&this);
	return -1;
}
